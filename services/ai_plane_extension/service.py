from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

from sqlalchemy import text
from sqlalchemy.orm import Session

from services.ai.audit import build_ai_audit_metadata
from services.ai.dispatch import ProviderCallError as _ProviderCallError
from services.ai.dispatch import call_provider as _call_provider
from services.ai_plane_extension import policy_engine, rag_stub
from services.ai_plane_extension.models import AIInferRequest, AIPolicyUpsertRequest
from services.phi_classifier.minimizer import minimize_prompt
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


class AIPlaneService:
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

    def _log_retrieval_stub(self, db: Session, tenant_id: str, prompt_sha: str) -> None:
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
                "inference_id": f"rag-{prompt_sha[:16]}-{self._next_inference_suffix(db, tenant_id, prompt_sha)}",
                "model_id": "RAG_STUB",
                "prompt_sha256": prompt_sha,
                "response_text": "RAG_STUB",
                "context_refs_json": "[]",
                "created_at_utc": _utc_now(),
                "output_sha256": "stub",
                "retrieval_id": "stub",
                "policy_result": "pass",
            },
        )

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

        effective_provider = _resolve_effective_provider()
        from fastapi import HTTPException as _HTTPException  # noqa: PLC0415
        from services.provider_baa.gate import (  # noqa: PLC0415
            enforce_baa_gate_for_route as _enforce_baa_gate,
        )

        pre_gate_prompt_sha = hashlib.sha256(payload.query.encode("utf-8")).hexdigest()
        request_id = f"inf-{pre_gate_prompt_sha[:16]}"
        try:
            baa_gate_result = _enforce_baa_gate(
                db,
                tenant_id=tenant_id,
                provider_id=effective_provider,
                text=payload.query,
                source="ai_plane_infer",
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
                        request_text=payload.query,
                        response_text=None,
                        request_id=request_id,
                    ),
                )
            self._record_violation(db, tenant_id, "AI_PHI_PROVIDER_NOT_BAA_CAPABLE")
            db.commit()
            raise ValueError("AI_PHI_PROVIDER_NOT_BAA_CAPABLE")

        prompt_minimization = minimize_prompt(payload.query)
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
                ),
            )
            self._record_violation(db, tenant_id, "AI_PROMPT_MINIMIZATION_FAILED")
            db.commit()
            raise ValueError("AI_PROMPT_MINIMIZATION_FAILED")

        prompt_sha = hashlib.sha256(outgoing_prompt.encode("utf-8")).hexdigest()
        request_id = f"inf-{prompt_sha[:16]}"
        rag = rag_stub.retrieve(tenant_id=tenant_id, query=payload.query)
        self._log_retrieval_stub(db, tenant_id, prompt_sha)

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
                "context_refs_json": json.dumps(rag.get("sources", [])),
                "created_at_utc": _utc_now(),
                "output_sha256": output_sha,
                "retrieval_id": str(rag.get("retrieval_id", "stub")),
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
