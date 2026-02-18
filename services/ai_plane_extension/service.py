from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone

from jsonschema import Draft202012Validator
from sqlalchemy import text
from sqlalchemy.orm import Session

from services.ai_plane_extension import policy_engine, rag_stub
from services.ai_plane_extension.models import AIInferRequest, AIPolicyUpsertRequest
from services.ai_plane_extension.orchestration import deterministic_simulated_response

SIM_MODEL = "SIMULATED_V1"


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


class AIPlaneService:
    def get_policy(self, db: Session, tenant_id: str) -> dict[str, object]:
        row = db.execute(
            text(
                "SELECT tenant_id, max_prompt_chars, blocked_topics_json "
                "FROM tenant_ai_policy WHERE tenant_id=:tenant_id"
            ),
            {"tenant_id": tenant_id},
        ).mappings().first()
        if row is None:
            return {"tenant_id": tenant_id, "max_prompt_chars": 2000, "denylist": []}
        blocked = row.get("blocked_topics_json") or "[]"
        if isinstance(blocked, str):
            denylist = json.loads(blocked)
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
                INSERT INTO tenant_ai_policy(tenant_id, max_prompt_chars, blocked_topics_json, require_human_review)
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
                "max_prompt_chars": payload.max_prompt_chars,
                "blocked_topics_json": json.dumps(payload.denylist),
            },
        )
        db.commit()
        return {
            "tenant_id": tenant_id,
            "max_prompt_chars": payload.max_prompt_chars,
            "denylist": payload.denylist,
        }

    def _record_violation(self, db: Session, tenant_id: str, code: str) -> None:
        db.execute(
            text(
                "INSERT INTO ai_policy_violations(tenant_id, violation_code, created_at) "
                "VALUES (:tenant_id, :violation_code, CURRENT_TIMESTAMP)"
            ),
            {"tenant_id": tenant_id, "violation_code": code},
        )

    def _next_inference_suffix(self, db: Session, tenant_id: str, prompt_sha: str) -> int:
        row = db.execute(
            text(
                "SELECT COUNT(*) AS c FROM ai_inference_records WHERE tenant_id=:tenant_id AND prompt_sha256=:prompt_sha256"
            ),
            {"tenant_id": tenant_id, "prompt_sha256": prompt_sha},
        ).mappings().first()
        return int((row or {}).get("c", 0)) + 1

    def _log_retrieval_stub(self, db: Session, tenant_id: str, prompt_sha: str) -> None:
        db.execute(
            text(
                """
                INSERT INTO ai_inference_records(tenant_id, inference_id, model_id, prompt_sha256, response_text, context_refs_json, created_at_utc, output_sha256, retrieval_id, policy_result, created_at)
                VALUES (:tenant_id, :inference_id, :model_id, :prompt_sha256, :response_text, :context_refs_json, :created_at_utc, :output_sha256, :retrieval_id, :policy_result, CURRENT_TIMESTAMP)
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

    def infer(self, db: Session, tenant_id: str, payload: AIInferRequest) -> dict[str, object]:
        policy = self.get_policy(db, tenant_id)
        if len(payload.query) > int(policy["max_prompt_chars"]):
            self._record_violation(db, tenant_id, "AI_INPUT_POLICY_BLOCKED")
            db.commit()
            raise ValueError("AI_INPUT_POLICY_BLOCKED")

        ok_in, code_in = policy_engine.evaluate_input(payload.query, policy["denylist"])
        if not ok_in:
            self._record_violation(db, tenant_id, code_in or "AI_INPUT_POLICY_BLOCKED")
            db.commit()
            raise ValueError("AI_INPUT_POLICY_BLOCKED")

        rag = rag_stub.retrieve(tenant_id=tenant_id, query=payload.query)
        prompt_sha = hashlib.sha256(payload.query.encode("utf-8")).hexdigest()
        self._log_retrieval_stub(db, tenant_id, prompt_sha)

        out = deterministic_simulated_response(payload.query)
        ok_out, code_out = policy_engine.evaluate_output(out)
        if not ok_out:
            self._record_violation(db, tenant_id, code_out or "AI_OUTPUT_POLICY_BLOCKED")
            db.commit()
            raise ValueError("AI_OUTPUT_POLICY_BLOCKED")

        output_sha = hashlib.sha256(out.encode("utf-8")).hexdigest()
        db.execute(
            text(
                """
                INSERT INTO ai_inference_records(tenant_id, inference_id, model_id, prompt_sha256, response_text, context_refs_json, created_at_utc, output_sha256, retrieval_id, policy_result, created_at)
                VALUES (:tenant_id, :inference_id, :model_id, :prompt_sha256, :response_text, :context_refs_json, :created_at_utc, :output_sha256, :retrieval_id, :policy_result, CURRENT_TIMESTAMP)
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

        return {
            "ok": True,
            "model": SIM_MODEL,
            "response": out,
            "simulated": True,
        }

    def list_inference(self, db: Session, tenant_id: str) -> list[dict[str, object]]:
        rows = db.execute(
            text(
                "SELECT id, prompt_sha256, output_sha256, retrieval_id, model_id, policy_result, created_at "
                "FROM ai_inference_records WHERE tenant_id=:tenant_id ORDER BY id DESC"
            ),
            {"tenant_id": tenant_id},
        ).mappings()
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
    payload = {
        "git_sha": git_sha,
        "timestamp": _utc_now(),
        "feature_flag_snapshot": feature_flag_snapshot,
        "total_inference_calls": int(total_inference_calls),
        "total_blocked_calls": int(total_blocked_calls),
        "total_policy_violations": int(total_policy_violations),
        "simulated_mode": True,
        "route_snapshot": sorted(route_snapshot),
    }
    with open(schema_path, encoding="utf-8") as f:
        schema = json.load(f)
    Draft202012Validator(schema).validate(payload)

    tmp_path = f"{out_path}.tmp"
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, sort_keys=True, indent=2)
        f.write("\n")
    os.replace(tmp_path, out_path)
    return payload
