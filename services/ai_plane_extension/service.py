from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, Sequence, cast

from sqlalchemy import text
from sqlalchemy.orm import Session

from api.rag.chunking import CorpusChunk
from services.ai.audit import build_ai_audit_metadata
from services.ai.dispatch import ProviderCallError as _ProviderCallError
from services.ai.dispatch import call_provider as _call_provider
from services.ai.dispatch import known_provider_ids
from services.ai.rag_context import (
    RagContextError,
    RagContextResult,
    build_rag_augmented_prompt,
    retrieve_rag_context,
)
from services.ai.routing import (
    AI_PROVIDER_NOT_CONFIGURED,
    configured_ai_providers,
    resolve_ai_provider_for_request,
)
from services.ai_plane_extension import policy_engine
from services.ai_plane_extension.models import AIInferRequest, AIPolicyUpsertRequest
from services.phi_classifier.minimizer import minimize_prompt
from services.phi_classifier.models import PhiClassificationResult, SensitivityLevel
from services.schema_validation import validate_payload_against_schema

if TYPE_CHECKING:
    from services.provider_baa.gate import BaaGateResult

_SIMULATED_MODEL = "SIMULATED_V1"
AI_PLANE_EVIDENCE_SCHEMA_VERSION = "v1"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def ai_plane_enabled() -> bool:
    return (os.getenv("FG_AI_PLANE_ENABLED") or "0").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def ai_external_provider_enabled() -> bool:
    return (os.getenv("FG_AI_EXTERNAL_PROVIDER_ENABLED") or "0").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def _resolve_effective_provider() -> str:
    """Deterministic provider selection: FG_AI_DEFAULT_PROVIDER > simulated fallback.

    FG_AI_EXTERNAL_PROVIDER_ENABLED is blocked at startup (main.py), so
    ai_external_provider_enabled() is preserved for that check only and is
    effectively always False at runtime.
    """
    env_default = (os.getenv("FG_AI_DEFAULT_PROVIDER") or "").strip()
    if env_default:
        return env_default
    fg_env = (os.getenv("FG_ENV") or "").strip().lower()
    if fg_env in {"prod", "production", "staging"}:
        raise ValueError("AI_PROVIDER_NOT_CONFIGURED")
    return "simulated"


def _int_or_default(value: object, default: int) -> int:
    return int(value) if isinstance(value, int) else default


def _str_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value]


def _ai_plane_allowed_providers() -> frozenset[str]:
    raw_env = os.getenv("FG_AI_ALLOWED_PROVIDERS")
    if raw_env is not None:
        return frozenset(
            item.strip() for item in raw_env.strip().split(",") if item.strip()
        )
    return configured_ai_providers()


def _canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _rag_retrieval_id(rag_context: RagContextResult) -> str:
    if not rag_context.rag_used:
        return "rag:none"
    payload = [
        {"chunk_id": chunk.chunk_id, "source_id": chunk.source_id}
        for chunk in rag_context.chunks
    ]
    digest = hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest()
    return f"rag:{digest[:24]}"


def _sensitivity_level(value: str | None) -> SensitivityLevel:
    try:
        return SensitivityLevel(value or SensitivityLevel.NONE.value)
    except ValueError:
        return SensitivityLevel.HIGH


def _merge_rag_phi_classification(
    classification: PhiClassificationResult,
    rag_context: RagContextResult,
) -> PhiClassificationResult:
    rag_context_contains_phi = any(
        (chunk.phi_sensitivity_level or "none") != "none" or chunk.phi_types
        for chunk in rag_context.chunks
    )
    if not rag_context_contains_phi:
        return classification

    rag_phi_types = frozenset(
        phi_type for chunk in rag_context.chunks for phi_type in chunk.phi_types
    )
    sensitivity = _sensitivity_level(rag_context.max_sensitivity_level)
    if _sensitivity_level(classification.sensitivity_level.value).value in {
        SensitivityLevel.MODERATE.value,
        SensitivityLevel.HIGH.value,
    }:
        sensitivity = classification.sensitivity_level
    if sensitivity == SensitivityLevel.NONE:
        sensitivity = SensitivityLevel.HIGH
    return PhiClassificationResult(
        contains_phi=True,
        phi_types=classification.phi_types | rag_phi_types,
        confidence=max(classification.confidence, 0.95),
        sensitivity_level=sensitivity,
        redaction_candidates=classification.redaction_candidates,
        reasoning_code="RAG_CONTEXT_PHI_DETECTED"
        if not classification.contains_phi
        else classification.reasoning_code,
    )


class AIPlaneService:
    def __init__(self, *, rag_chunks: Sequence[CorpusChunk] | None = None) -> None:
        self._rag_chunks: tuple[CorpusChunk, ...] = tuple(rag_chunks or ())

    def get_policy(self, db: Session, tenant_id: str) -> dict[str, object]:
        row = (
            db.execute(
                text(
                    "SELECT tenant_id, max_prompt_chars, blocked_topics_json "
                    "FROM tenant_ai_policy WHERE tenant_id=:tenant_id"
                ),
                {"tenant_id": tenant_id},
            )
            .mappings()
            .first()
        )

        if row is None:
            return {"tenant_id": tenant_id, "max_prompt_chars": 2000, "denylist": []}

        blocked = row.get("blocked_topics_json") or "[]"
        if isinstance(blocked, str):
            try:
                denylist = json.loads(blocked)
            except json.JSONDecodeError:
                denylist = []
        else:
            denylist = blocked

        return {
            "tenant_id": tenant_id,
            "max_prompt_chars": int(row.get("max_prompt_chars") or 2000),
            "denylist": [str(x) for x in (denylist or [])],
        }

    def upsert_policy(
        self, db: Session, tenant_id: str, payload: AIPolicyUpsertRequest
    ) -> dict[str, object]:
        db.execute(
            text(
                """
                INSERT INTO tenant_ai_policy(
                    tenant_id, max_prompt_chars, blocked_topics_json, require_human_review
                )
                VALUES (:tenant_id, :max_prompt_chars, :blocked_topics_json, 1)
                ON CONFLICT(tenant_id)
                DO UPDATE SET
                    max_prompt_chars = excluded.max_prompt_chars,
                    blocked_topics_json = excluded.blocked_topics_json,
                    updated_at = CURRENT_TIMESTAMP
                """
            ),
            {
                "tenant_id": tenant_id,
                "max_prompt_chars": int(payload.max_prompt_chars),
                "blocked_topics_json": json.dumps(payload.denylist),
            },
        )
        db.commit()
        return {
            "tenant_id": tenant_id,
            "max_prompt_chars": int(payload.max_prompt_chars),
            "denylist": list(payload.denylist),
        }

    def _record_violation(self, db: Session, tenant_id: str, code: str) -> None:
        db.execute(
            text(
                "INSERT INTO ai_policy_violations(tenant_id, violation_code, created_at) "
                "VALUES (:tenant_id, :violation_code, CURRENT_TIMESTAMP)"
            ),
            {"tenant_id": tenant_id, "violation_code": code},
        )

    def _audit_infer(
        self,
        *,
        tenant_id: str,
        success: bool,
        reason: str,
        details: dict[str, object],
    ) -> None:
        from api.security_audit import AuditEvent, EventType, Severity, get_auditor  # noqa: PLC0415

        get_auditor().log_event(
            AuditEvent(
                event_type=EventType.ADMIN_ACTION,
                success=success,
                severity=Severity.INFO if success else Severity.WARNING,
                tenant_id=tenant_id,
                reason=reason,
                details=details,
            )
        )

    def _next_inference_suffix(
        self, db: Session, tenant_id: str, prompt_sha: str
    ) -> int:
        row = (
            db.execute(
                text(
                    "SELECT COUNT(*) AS c "
                    "FROM ai_inference_records "
                    "WHERE tenant_id=:tenant_id AND prompt_sha256=:prompt_sha256"
                ),
                {"tenant_id": tenant_id, "prompt_sha256": prompt_sha},
            )
            .mappings()
            .first()
        )
        if row is None:
            return 1
        count = row.get("c")
        return (count if isinstance(count, int) else 0) + 1

    def infer(
        self, db: Session, tenant_id: str, payload: AIInferRequest
    ) -> dict[str, object]:
        policy = self.get_policy(db, tenant_id)
        max_prompt_chars = _int_or_default(policy.get("max_prompt_chars"), 2000)
        denylist = _str_list(policy.get("denylist"))

        if len(payload.query) > max_prompt_chars:
            self._record_violation(db, tenant_id, "AI_INPUT_POLICY_BLOCKED")
            db.commit()
            raise ValueError("AI_INPUT_POLICY_BLOCKED")

        ok_in, code_in = policy_engine.evaluate_input(payload.query, denylist)
        if not ok_in:
            self._record_violation(db, tenant_id, code_in or "AI_INPUT_POLICY_BLOCKED")
            db.commit()
            raise ValueError("AI_INPUT_POLICY_BLOCKED")

        from fastapi import HTTPException as _HTTPException  # noqa: PLC0415
        from services.provider_baa.gate import (  # noqa: PLC0415
            classify_baa_gate_phi as _classify_baa_gate_phi,
            enforce_baa_gate_for_route as _enforce_baa_gate,
        )

        pre_gate_prompt_sha = hashlib.sha256(payload.query.encode("utf-8")).hexdigest()
        request_id = f"inf-{pre_gate_prompt_sha[:16]}"
        phi_classification = _classify_baa_gate_phi(payload.query)
        try:
            rag_context = retrieve_rag_context(
                tenant_id=tenant_id,
                query_text=payload.query,
                chunks=self._rag_chunks,
                limit=4,
                phi_detected=phi_classification.contains_phi,
                query_phi_sensitivity=phi_classification.sensitivity_level.value,
            )
        except RagContextError as exc:
            self._audit_infer(
                tenant_id=tenant_id,
                success=False,
                reason=exc.error_code,
                details={
                    "provider_id": None,
                    "requested_provider": None,
                    "selected_by": None,
                    "routing_reason_code": None,
                    "phi_detected": phi_classification.contains_phi,
                    "phi_types": sorted(
                        phi_classification.phi_types - {"medical_keyword"}
                    ),
                    "baa_check_result": "not_evaluated",
                    "prompt_minimized": False,
                    "request_hash": None,
                    "response_hash": None,
                    "rag_used": False,
                    "rag_chunk_count": 0,
                    "rag_source_ids": [],
                    "rag_retrieval_reason_code": exc.error_code,
                    "rag_query_phi_sensitivity": phi_classification.sensitivity_level.value,
                    "rag_max_sensitivity_level": None,
                },
            )
            self._record_violation(db, tenant_id, exc.error_code)
            db.commit()
            raise ValueError(exc.error_code) from exc

        provider_prompt = build_rag_augmented_prompt(
            query_text=payload.query, rag_context=rag_context
        )
        final_phi_classification = (
            _classify_baa_gate_phi(provider_prompt)
            if rag_context.rag_used
            else phi_classification
        )
        final_phi_classification = _merge_rag_phi_classification(
            final_phi_classification, rag_context
        )
        guarded_default_provider = (
            None
            if final_phi_classification.contains_phi
            else _resolve_effective_provider()
        )
        routing_result = resolve_ai_provider_for_request(
            tenant_id=tenant_id,
            requested_provider=None,
            tenant_allowed_providers=_ai_plane_allowed_providers(),
            known_providers=known_provider_ids(),
            configured_providers=configured_ai_providers(),
            phi_detected=final_phi_classification.contains_phi,
            default_provider=guarded_default_provider,
            phi_provider=(os.getenv("FG_AI_PHI_PROVIDER") or "").strip() or None,
        )
        if not routing_result.allowed or routing_result.provider_id is None:
            self._audit_infer(
                tenant_id=tenant_id,
                success=False,
                reason=routing_result.reason_code,
                details={
                    "provider_id": routing_result.provider_id,
                    "requested_provider": routing_result.requested_provider,
                    "selected_by": routing_result.selected_by,
                    "routing_reason_code": routing_result.reason_code,
                    "phi_detected": final_phi_classification.contains_phi,
                    "phi_types": sorted(
                        final_phi_classification.phi_types - {"medical_keyword"}
                    ),
                    "baa_check_result": "not_evaluated",
                    "prompt_minimized": False,
                    "request_hash": None,
                    "response_hash": None,
                    "rag_used": rag_context.rag_used,
                    "rag_chunk_count": rag_context.chunk_count,
                    "rag_source_ids": list(rag_context.source_ids),
                    "rag_retrieval_reason_code": rag_context.retrieval_reason_code,
                    "rag_query_phi_sensitivity": rag_context.query_phi_sensitivity,
                    "rag_max_sensitivity_level": rag_context.max_sensitivity_level,
                },
            )
            self._record_violation(db, tenant_id, routing_result.reason_code)
            db.commit()
            if routing_result.reason_code == AI_PROVIDER_NOT_CONFIGURED:
                raise ValueError("AI_PROVIDER_NOT_CONFIGURED")
            raise ValueError(routing_result.reason_code)

        effective_provider = routing_result.provider_id
        try:
            baa_gate_result = _enforce_baa_gate(
                db,
                tenant_id=tenant_id,
                provider_id=effective_provider,
                text=provider_prompt,
                source="ai_plane_infer",
                classification=final_phi_classification,
            )
        except _HTTPException as exc:
            denied_baa_gate_result = cast(
                "BaaGateResult | None", getattr(exc, "baa_gate_result", None)
            )
            if denied_baa_gate_result is not None:
                self._audit_infer(
                    tenant_id=tenant_id,
                    success=False,
                    reason="AI_PHI_PROVIDER_NOT_BAA_CAPABLE",
                    details=build_ai_audit_metadata(
                        tenant_id=tenant_id,
                        provider_id=effective_provider,
                        baa_gate_result=denied_baa_gate_result,
                        request_text=provider_prompt,
                        response_text=None,
                        request_id=request_id,
                        routing_result=routing_result,
                        rag_context=rag_context,
                    ),
                )
            self._record_violation(db, tenant_id, "AI_PHI_PROVIDER_NOT_BAA_CAPABLE")
            db.commit()
            raise ValueError("AI_PHI_PROVIDER_NOT_BAA_CAPABLE")

        prompt_minimization = minimize_prompt(provider_prompt, final_phi_classification)
        outgoing_prompt = prompt_minimization.minimized_text
        if prompt_minimization.reason_code == "PROMPT_MINIMIZATION_NON_STRING":
            self._audit_infer(
                tenant_id=tenant_id,
                success=False,
                reason="AI_PROMPT_MINIMIZATION_FAILED",
                details=build_ai_audit_metadata(
                    tenant_id=tenant_id,
                    provider_id=effective_provider,
                    baa_gate_result=baa_gate_result,
                    request_text="",
                    response_text=None,
                    prompt_minimization=prompt_minimization,
                    request_id=request_id,
                    routing_result=routing_result,
                    rag_context=rag_context,
                ),
            )
            self._record_violation(db, tenant_id, "AI_PROMPT_MINIMIZATION_FAILED")
            db.commit()
            raise ValueError("AI_PROMPT_MINIMIZATION_FAILED")

        prompt_sha = hashlib.sha256(outgoing_prompt.encode("utf-8")).hexdigest()
        request_id = f"inf-{prompt_sha[:16]}"

        try:
            prov_resp = _call_provider(
                provider_id=effective_provider,
                prompt=outgoing_prompt,
                max_tokens=2000,
                request_id=request_id,
                tenant_id=tenant_id,
            )
        except _ProviderCallError as exc:
            self._audit_infer(
                tenant_id=tenant_id,
                success=False,
                reason=exc.error_code,
                details=build_ai_audit_metadata(
                    tenant_id=tenant_id,
                    provider_id=effective_provider,
                    baa_gate_result=baa_gate_result,
                    request_text=outgoing_prompt,
                    response_text=None,
                    prompt_minimization=prompt_minimization,
                    request_id=request_id,
                    routing_result=routing_result,
                    rag_context=rag_context,
                ),
            )
            self._record_violation(db, tenant_id, exc.error_code)
            db.commit()
            raise ValueError(exc.error_code) from exc

        out = prov_resp.text
        ok_out, code_out = policy_engine.evaluate_output(out)
        if not ok_out:
            self._record_violation(
                db, tenant_id, code_out or "AI_OUTPUT_POLICY_BLOCKED"
            )
            db.commit()
            raise ValueError("AI_OUTPUT_POLICY_BLOCKED")

        output_sha = hashlib.sha256(out.encode("utf-8")).hexdigest()

        db.execute(
            text(
                """
                INSERT INTO ai_inference_records(
                    tenant_id, inference_id, model_id, prompt_sha256, response_text,
                    context_refs_json, created_at_utc, output_sha256, retrieval_id,
                    policy_result, created_at
                )
                VALUES (
                    :tenant_id, :inference_id, :model_id, :prompt_sha256, :response_text,
                    :context_refs_json, :created_at_utc, :output_sha256, :retrieval_id,
                    :policy_result, CURRENT_TIMESTAMP
                )
                """
            ),
            {
                "tenant_id": tenant_id,
                "inference_id": f"inf-{prompt_sha[:16]}-{self._next_inference_suffix(db, tenant_id, prompt_sha)}",
                "model_id": prov_resp.model,
                "prompt_sha256": prompt_sha,
                "response_text": out,
                "context_refs_json": _canonical_json(list(rag_context.source_ids)),
                "created_at_utc": _utc_now(),
                "output_sha256": output_sha,
                "retrieval_id": _rag_retrieval_id(rag_context),
                "policy_result": "pass",
            },
        )
        db.commit()

        self._audit_infer(
            tenant_id=tenant_id,
            success=True,
            reason="ai_plane_infer",
            details=build_ai_audit_metadata(
                tenant_id=tenant_id,
                provider_id=effective_provider,
                baa_gate_result=baa_gate_result,
                request_text=outgoing_prompt,
                provider_response=prov_resp,
                prompt_minimization=prompt_minimization,
                request_id=request_id,
                routing_result=routing_result,
                rag_context=rag_context,
            ),
        )

        return {
            "ok": True,
            "provider": effective_provider,
            "model": prov_resp.model,
            "response": out,
            "simulated": effective_provider == "simulated",
        }

    def list_inference(self, db: Session, tenant_id: str) -> list[dict[str, object]]:
        rows = (
            db.execute(
                text(
                    "SELECT id, prompt_sha256, output_sha256, retrieval_id, model_id, policy_result, created_at "
                    "FROM ai_inference_records WHERE tenant_id=:tenant_id ORDER BY id DESC"
                ),
                {"tenant_id": tenant_id},
            )
            .mappings()
            .all()
        )
        return [dict(r) for r in rows]


def write_ai_plane_evidence(
    *,
    out_path: str,
    schema_path: str,
    git_sha: str,
    feature_flag_snapshot: dict[str, object],
    total_inference_calls: int,
    total_blocked_calls: int,
    total_policy_violations: int,
    route_snapshot: list[str],
) -> dict[str, object]:
    # Build payload deterministically.
    payload: dict[str, Any] = {
        "schema_version": "v1",
        "plane_id": "ai_plane",
        "git_sha": str(git_sha),
        "timestamp": _utc_now(),
        "feature_flag_snapshot": dict(feature_flag_snapshot),
        "total_inference_calls": int(total_inference_calls),
        "total_blocked_calls": int(total_blocked_calls),
        "total_policy_violations": int(total_policy_violations),
        "simulated_mode": True,
        "route_snapshot": sorted(set(route_snapshot)),
    }

    schema = json.loads(Path(schema_path).read_text(encoding="utf-8"))
    validate_payload_against_schema(payload, schema)

    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)

    tmp = out.with_suffix(out.suffix + ".tmp")
    data = (json.dumps(payload, sort_keys=True, indent=2) + "\n").encode("utf-8")

    with tmp.open("wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())

    os.chmod(tmp, 0o600)
    os.replace(tmp, out)
    return payload
