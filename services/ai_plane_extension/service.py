from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session

from services.ai_plane_extension import policy_engine, rag_stub
from services.ai_plane_extension.models import AIInferRequest, AIPolicyUpsertRequest
from services.ai_plane_extension.orchestration import deterministic_simulated_response
from services.schema_validation import validate_payload_against_schema

SIM_MODEL = "SIMULATED_V1"
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

        # BAA enforcement gate: resolve the effective provider and enforce
        # before any inference work. SIM_MODEL is non-regulated; this path
        # is a no-op today but establishes the enforcement point for when
        # real external providers are wired into this service.
        from services.provider_baa.policy import enforce_provider_baa_for_route  # noqa: PLC0415

        effective_provider = (
            "simulated" if not ai_external_provider_enabled() else SIM_MODEL.lower()
        )
        try:
            enforce_provider_baa_for_route(
                db, tenant_id=tenant_id, provider_id=effective_provider
            )
        except Exception as baa_exc:
            from fastapi import HTTPException as _HTTPException  # noqa: PLC0415

            if isinstance(baa_exc, _HTTPException):
                self._record_violation(db, tenant_id, "AI_PROVIDER_BAA_DENIED")
                db.commit()
                detail = baa_exc.detail
                err_code = (
                    detail.get("error_code", "AI_PROVIDER_BAA_DENIED")
                    if isinstance(detail, dict)
                    else "AI_PROVIDER_BAA_DENIED"
                )
                raise ValueError(err_code) from baa_exc
            raise

        # PHI classification: runs after BAA gate, before any inference.
        # PHI + non-BAA-eligible provider → record violation and deny.
        from services.phi_classifier.classifier import (  # noqa: PLC0415
            classify_phi as _classify_phi,
            emit_phi_classification_audit as _emit_phi_audit,
            emit_phi_enforcement_block_audit as _emit_phi_block_audit,
        )
        from services.provider_baa.policy import requires_baa as _requires_baa  # noqa: PLC0415

        _phi_result = _classify_phi(payload.query)
        if _phi_result.contains_phi and not _requires_baa(effective_provider):
            _emit_phi_block_audit(
                _phi_result,
                tenant_id=tenant_id,
                provider_id=effective_provider,
            )
            self._record_violation(db, tenant_id, "AI_PHI_PROVIDER_NOT_BAA_CAPABLE")
            db.commit()
            raise ValueError("AI_PHI_PROVIDER_NOT_BAA_CAPABLE")
        _emit_phi_audit(_phi_result, tenant_id=tenant_id, enforcement_action="allowed")

        rag = rag_stub.retrieve(tenant_id=tenant_id, query=payload.query)
        prompt_sha = hashlib.sha256(payload.query.encode("utf-8")).hexdigest()
        self._log_retrieval_stub(db, tenant_id, prompt_sha)

        out = deterministic_simulated_response(payload.query)
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
                "model_id": SIM_MODEL,
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

        return {"ok": True, "model": SIM_MODEL, "response": out, "simulated": True}

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
