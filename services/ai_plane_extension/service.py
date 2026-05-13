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
from api.rag_reranking import RerankConfig
from api.rag_retrieval_policy_store import get_retrieval_policy, rag_rules_from_db
from services.ai.audit import build_ai_audit_metadata
from services.ai.dispatch import ProviderCallError as _ProviderCallError
from services.ai.dispatch import call_provider as _call_provider
from services.ai.dispatch import known_provider_ids
from services.ai.policy import AiPolicyError, AiRagRules, resolve_ai_policy_for_tenant
from services.ai.rag_context import (
    RagContextError,
    RagContextResult,
    build_rag_augmented_prompt,
    retrieve_persisted_rag_context,
    retrieve_rag_context,
)
from services.ai.provenance import validate_answer_provenance
from services.ai.response_validation import ResponseValidationResult
from services.ai.response_validation import validate_provider_response_grounding
from services.ai.routing import (
    AI_PROVIDER_NOT_CONFIGURED,
    configured_ai_providers,
    resolve_ai_provider_for_request,
)
from services.ai_plane_extension import policy_engine
from services.ai_plane_extension.models import (
    AIChatRequest,
    ComplianceMode,
    EvidenceAwareResponse,
    AIInferRequest,
    AIPolicyUpsertRequest,
)
from services.phi_classifier.minimizer import minimize_prompt
from services.phi_classifier.models import PhiClassificationResult, SensitivityLevel
from services.schema_validation import validate_payload_against_schema

if TYPE_CHECKING:
    from services.provider_baa.gate import BaaGateResult

_SIMULATED_MODEL = "SIMULATED_V1"
AI_PLANE_EVIDENCE_SCHEMA_VERSION = "v1"
_DEFAULT_COMPLIANCE_MODE: ComplianceMode = "retrieval_preferred"
_REGULATED_MODES = frozenset({"phi_restricted", "legal_grade", "finance_grade"})
_LEGAL_TERMS = frozenset({"legal", "contract", "liability", "lawsuit", "regulation"})
_FINANCE_TERMS = frozenset({"finance", "financial", "revenue", "invoice", "payment"})
_REVIEW_THRESHOLDS: dict[ComplianceMode, float] = {
    "strict_grounded": 0.25,
    "retrieval_preferred": 0.70,
    "phi_restricted": 0.35,
    "legal_grade": 0.35,
    "finance_grade": 0.35,
    "internal_ops": 0.55,
}


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


def _rag_answer_metadata(rag_context: RagContextResult) -> dict[str, object]:
    return {
        "used_rag": rag_context.rag_used,
        "context_count": rag_context.chunk_count,
        "source_chunk_ids": list(rag_context.source_chunk_ids),
    }


def _safe_source_summaries(rag_context: RagContextResult) -> list[dict[str, object]]:
    included_chunk_ids = set(rag_context.source_chunk_ids)
    return [
        {
            "source_id": chunk.source_id,
            "chunk_id": chunk.chunk_id,
            "chunk_index": chunk.chunk_index,
            "included_in_prompt": chunk.chunk_id in included_chunk_ids,
            "phi_sensitivity_level": chunk.phi_sensitivity_level,
            "phi_types": list(chunk.phi_types),
        }
        for chunk in rag_context.chunks
    ]


def _safe_why_this_chunk(rag_context: RagContextResult) -> dict[str, object]:
    included_chunk_ids = set(rag_context.source_chunk_ids)
    return {
        chunk.chunk_id: dict(chunk.why_this_chunk)
        for chunk in rag_context.chunks
        if chunk.chunk_id in included_chunk_ids and chunk.why_this_chunk is not None
    }


def _rag_provenance_ui_metadata(
    rag_context: RagContextResult,
    response_validation: ResponseValidationResult,
) -> dict[str, object]:
    return {
        "retrieval_trace_id": rag_context.retrieval_trace_id,
        "used_rag": rag_context.rag_used,
        "context_count": rag_context.chunk_count,
        "source_chunk_ids": list(rag_context.source_chunk_ids),
        "source_summaries": _safe_source_summaries(rag_context),
        "confidence": rag_context.confidence,
        "why_this_chunk": _safe_why_this_chunk(rag_context),
        "retrieval_strategy": rag_context.retrieval_strategy,
        "provenance_status": response_validation.provenance_reason_code,
    }


def _resolve_compliance_mode(
    *,
    requested_mode: ComplianceMode | None,
    query_text: str,
    phi_detected: bool,
) -> ComplianceMode:
    if requested_mode is not None:
        return requested_mode
    if phi_detected:
        return "phi_restricted"
    query_terms = set(str(query_text).lower().split())
    if query_terms & _LEGAL_TERMS:
        return "legal_grade"
    if query_terms & _FINANCE_TERMS:
        return "finance_grade"
    return _DEFAULT_COMPLIANCE_MODE


def _bounded_confidence(*values: float | None) -> float:
    for value in values:
        if isinstance(value, int | float) and not isinstance(value, bool):
            return max(0.0, min(float(value), 1.0))
    return 0.0


def _safe_support_summary(chunk_index: int) -> str:
    return f"Source-backed retrieved chunk #{chunk_index + 1}; raw chunk text omitted."


def _evidence_for_response(
    *,
    rag_context: RagContextResult,
    response_validation: ResponseValidationResult,
) -> list[dict[str, object]]:
    if (
        not response_validation.grounded
        or response_validation.provenance_valid is False
    ):
        return []
    cited = set(response_validation.citation_source_ids)
    evidence: list[dict[str, object]] = []
    for chunk in rag_context.chunks:
        if chunk.source_id not in cited and chunk.chunk_id not in cited:
            continue
        evidence.append(
            {
                "doc_id": chunk.doc_id or chunk.source_id,
                "chunk_id": chunk.chunk_id,
                "source_hash": chunk.source_hash,
                "corpus_id": chunk.corpus_id,
                "citation_label": chunk.source_id,
                "source_title": chunk.source_title,
                "support_summary": _safe_support_summary(chunk.chunk_index),
                "confidence": _bounded_confidence(
                    chunk.confidence, rag_context.confidence, 1.0
                ),
                "retrieval_rank": chunk.retrieval_rank or chunk.chunk_index + 1,
                "rerank_score": _bounded_confidence(chunk.rerank_score)
                if chunk.rerank_score is not None
                else None,
                "provenance_status": response_validation.provenance_reason_code,
            }
        )
    return evidence


def _uncertainty_item(
    *,
    issue: str,
    reason_code: str,
    affected_claim_or_area: str,
    severity: str,
    evidence_refs: list[str] | None = None,
) -> dict[str, object]:
    return {
        "issue": issue,
        "reason_code": reason_code,
        "affected_claim_or_area": affected_claim_or_area,
        "severity": severity,
        "evidence_refs": evidence_refs or [],
    }


def _corpus_disagreement_detected(rag_context: RagContextResult) -> bool:
    corpus_ids = {chunk.corpus_id for chunk in rag_context.chunks if chunk.corpus_id}
    if len(corpus_ids) < 2:
        return False
    conflict_markers = ("conflict", "contradict", "disagree", "different value")
    return any(
        marker in chunk.text.lower()
        for chunk in rag_context.chunks
        for marker in conflict_markers
    )


def _build_evidence_aware_response(
    *,
    answer: str,
    rag_context: RagContextResult,
    response_validation: ResponseValidationResult,
    compliance_mode: ComplianceMode,
    retrieval_policy_applied: bool,
    effective_rag_rules: AiRagRules,
    policy_version: int | None,
) -> dict[str, object]:
    evidence = _evidence_for_response(
        rag_context=rag_context, response_validation=response_validation
    )
    evidence_refs = [str(item["chunk_id"]) for item in evidence]
    uncertainty: list[dict[str, object]] = []
    risk_factors: list[str] = []

    if not evidence:
        uncertainty.append(
            _uncertainty_item(
                issue="No source-backed evidence supports the final answer.",
                reason_code="missing_evidence",
                affected_claim_or_area="answer",
                severity="high",
            )
        )
        risk_factors.append("missing_evidence")
    missing_hash_refs = [
        str(item["chunk_id"]) for item in evidence if not item.get("source_hash")
    ]
    if missing_hash_refs:
        uncertainty.append(
            _uncertainty_item(
                issue="One or more evidence items lacks source hash proof.",
                reason_code="source_hash_missing",
                affected_claim_or_area="evidence",
                severity="medium",
                evidence_refs=missing_hash_refs,
            )
        )
        risk_factors.append("source_hash_missing")
    if response_validation.provenance_valid is False:
        reason_code = response_validation.provenance_reason_code or "citation_invalid"
        uncertainty.append(
            _uncertainty_item(
                issue="Citation/provenance validation failed.",
                reason_code="citation_invalid",
                affected_claim_or_area="citations",
                severity="high",
            )
        )
        risk_factors.append(str(reason_code))
    if response_validation.reason_code not in {"RESPONSE_GROUNDED"}:
        uncertainty.append(
            _uncertainty_item(
                issue="Grounded-answer validation did not approve the provider answer.",
                reason_code="weak_evidence"
                if rag_context.rag_used
                else "missing_evidence",
                affected_claim_or_area="answer",
                severity="high" if not rag_context.rag_used else "medium",
            )
        )
        risk_factors.append(response_validation.reason_code)
    if rag_context.confidence is not None and rag_context.confidence < 0.50:
        uncertainty.append(
            _uncertainty_item(
                issue="Retrieval confidence is below the evidence threshold.",
                reason_code="weak_evidence",
                affected_claim_or_area="retrieval",
                severity="medium",
                evidence_refs=evidence_refs,
            )
        )
        risk_factors.append("low_retrieval_confidence")
    if _corpus_disagreement_detected(rag_context):
        uncertainty.append(
            _uncertainty_item(
                issue="Retrieved corpus evidence contains conflict markers.",
                reason_code="corpus_disagreement",
                affected_claim_or_area="multi_corpus_evidence",
                severity="high",
                evidence_refs=evidence_refs,
            )
        )
        risk_factors.append("corpus_disagreement")
    if compliance_mode in _REGULATED_MODES:
        uncertainty.append(
            _uncertainty_item(
                issue="Regulated compliance mode requires elevated review sensitivity.",
                reason_code="regulated_domain",
                affected_claim_or_area=compliance_mode,
                severity="medium",
                evidence_refs=evidence_refs,
            )
        )
        risk_factors.append("regulated_domain")
    if (
        rag_context.retrieval_policy_reason_code
        and rag_context.retrieval_policy_reason_code != "RETRIEVAL_POLICY_ALLOWED"
    ):
        uncertainty.append(
            _uncertainty_item(
                issue="Retrieval policy changed or restricted the requested retrieval path.",
                reason_code="policy_restricted",
                affected_claim_or_area="retrieval_policy",
                severity="medium",
            )
        )
        risk_factors.append(str(rag_context.retrieval_policy_reason_code))

    inference: list[dict[str, object]] = []
    if response_validation.grounded and evidence:
        inference.append(
            {
                "claim": "Final answer is grounded in retrieved evidence references.",
                "based_on_evidence_refs": evidence_refs,
                "confidence": _bounded_confidence(rag_context.confidence, 1.0),
                "reasoning_type": "grounded_extractive_validation",
                "limitation": None,
            }
        )

    risk = (
        0.05 if evidence and response_validation.provenance_valid is not False else 0.75
    )
    weights = {
        "missing_evidence": 0.30,
        "source_hash_missing": 0.15,
        "low_retrieval_confidence": 0.15,
        "regulated_domain": 0.15,
        "corpus_disagreement": 0.25,
        "policy_restricted": 0.15,
        "RESPONSE_UNGROUNDED": 0.25,
        "RESPONSE_NO_RAG_CONTEXT": 0.25,
        "RESPONSE_EMPTY": 0.20,
        "PROVENANCE_SOURCE_NOT_RETRIEVED": 0.30,
        "PROVENANCE_SOURCE_NOT_IN_PROMPT": 0.30,
        "PROVENANCE_NO_CONTEXT_AVAILABLE": 0.20,
        "RETRIEVAL_POLICY_LEXICAL_FALLBACK": 0.10,
        "RETRIEVAL_POLICY_EMPTY_SCOPE": 0.25,
    }
    for factor in dict.fromkeys(risk_factors):
        risk += weights.get(factor, 0.10)
    if (
        rag_context.confidence is not None
        and rag_context.confidence >= 0.80
        and evidence
    ):
        risk -= 0.05
    risk_score = round(max(0.0, min(risk, 1.0)), 4)

    review_reasons: list[str] = []
    threshold = _REVIEW_THRESHOLDS[compliance_mode]
    if risk_score >= threshold:
        review_reasons.append("risk_threshold_exceeded")
    if compliance_mode == "strict_grounded" and not evidence:
        review_reasons.append("strict_grounded_missing_evidence")
    if compliance_mode in _REGULATED_MODES and (
        "missing_evidence" in risk_factors or "low_retrieval_confidence" in risk_factors
    ):
        review_reasons.append("regulated_mode_weak_evidence")
    if response_validation.provenance_valid is False:
        review_reasons.append("provenance_validation_failed")
    if "corpus_disagreement" in risk_factors:
        review_reasons.append("corpus_disagreement")
    if (
        effective_rag_rules.require_grounded_response
        and not response_validation.grounded
    ):
        review_reasons.append("grounded_response_required")

    response = EvidenceAwareResponse.model_validate(
        {
            "answer": answer,
            "evidence": evidence,
            "inference": inference,
            "uncertainty": uncertainty,
            "risk_score": risk_score,
            "requires_human_review": bool(review_reasons),
            "review_reasons": sorted(dict.fromkeys(review_reasons)),
            "compliance_mode": compliance_mode,
            "retrieval_mode": rag_context.retrieval_strategy,
            "policy_version": policy_version,
            "provenance_status": response_validation.provenance_reason_code,
            "retrieval_policy_applied": retrieval_policy_applied,
            "confidence": _bounded_confidence(
                rag_context.confidence, _chat_confidence(response_validation)
            ),
            "answer_reason": response_validation.reason_code,
            "no_answer_reason": response_validation.reason_code
            if answer == "NO_ANSWER"
            else None,
            "risk_factors": sorted(dict.fromkeys(risk_factors)),
        }
    )
    return response.model_dump()


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


def _chat_sources(
    response_validation: ResponseValidationResult,
) -> list[dict[str, str]]:
    if not response_validation.grounded:
        return []
    return [
        {"source_id": source_id}
        for source_id in dict.fromkeys(response_validation.citation_source_ids)
        if source_id
    ]


def _chat_confidence(response_validation: ResponseValidationResult) -> float:
    if response_validation.grounded and response_validation.evidence_count > 0:
        return 1.0
    return 0.0


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
        try:
            ai_policy = resolve_ai_policy_for_tenant(
                tenant_id=tenant_id,
                known_providers=known_provider_ids(),
                environment=os.getenv("FG_ENV"),
            )
        except AiPolicyError as exc:
            self._audit_infer(
                tenant_id=tenant_id,
                success=False,
                reason=exc.error_code,
                details={
                    "policy_source": None,
                    "policy_version": None,
                    "policy_reason_code": exc.error_code,
                    "provider_id": None,
                    "requested_provider": None,
                    "selected_by": None,
                    "routing_reason_code": None,
                    "phi_detected": False,
                    "phi_types": [],
                    "baa_check_result": "not_evaluated",
                    "prompt_minimized": False,
                    "request_hash": None,
                    "response_hash": None,
                    "rag_used": False,
                    "rag_chunk_count": 0,
                    "rag_source_ids": [],
                    "rag_source_chunk_ids": [],
                    "rag_retrieval_reason_code": None,
                    "rag_query_phi_sensitivity": None,
                    "rag_max_sensitivity_level": None,
                    "response_grounded": False,
                    "response_validation_result": None,
                    "response_validator_version": None,
                    "response_citation_source_ids": [],
                    "response_evidence_count": 0,
                },
            )
            self._record_violation(db, tenant_id, exc.error_code)
            db.commit()
            raise ValueError(exc.error_code) from exc
        max_prompt_chars = _int_or_default(policy.get("max_prompt_chars"), 2000)
        denylist = _str_list(policy.get("denylist"))

        # Load DB-stored retrieval policy; takes precedence over file-based rag_rules.
        # Falls back to ai_policy.rag_rules when no row exists (backward compatible).
        _stored_retrieval_policy = get_retrieval_policy(db, tenant_id)
        _db_rag_rules = rag_rules_from_db(db, tenant_id)
        effective_rag_rules: AiRagRules = (
            _db_rag_rules if _db_rag_rules is not None else ai_policy.rag_rules
        )
        # Gate reranker: when DB policy exists, respect reranking_enabled flag.
        # When no DB policy row exists, pass None (retrieve_persisted_rag_context
        # default: RerankConfig(enabled=True) — preserves existing behavior).
        _rerank_config: RerankConfig | None = None
        if _stored_retrieval_policy is not None:
            _rerank_config = RerankConfig(
                enabled=bool(_stored_retrieval_policy.get("reranking_enabled", True))
            )

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
        compliance_mode = _resolve_compliance_mode(
            requested_mode=payload.compliance_mode,
            query_text=payload.query,
            phi_detected=phi_classification.contains_phi,
        )
        try:
            if self._rag_chunks:
                rag_context = retrieve_rag_context(
                    tenant_id=tenant_id,
                    query_text=payload.query,
                    chunks=self._rag_chunks,
                    limit=4,
                    phi_detected=phi_classification.contains_phi,
                    query_phi_sensitivity=phi_classification.sensitivity_level.value,
                )
            else:
                rag_context = retrieve_persisted_rag_context(
                    db=db,
                    tenant_id=tenant_id,
                    query_text=payload.query,
                    limit=4,
                    phi_detected=phi_classification.contains_phi,
                    query_phi_sensitivity=phi_classification.sensitivity_level.value,
                    rag_rules=effective_rag_rules,
                    rerank_config=_rerank_config,
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
                    "rag_source_chunk_ids": [],
                    "rag_retrieval_reason_code": exc.error_code,
                    "rag_query_phi_sensitivity": phi_classification.sensitivity_level.value,
                    "rag_max_sensitivity_level": None,
                    "response_grounded": False,
                    "response_validation_result": None,
                    "response_validator_version": None,
                    "response_citation_source_ids": [],
                    "response_evidence_count": 0,
                    "policy_source": ai_policy.source,
                    "policy_version": ai_policy.version,
                    "policy_reason_code": ai_policy.reason_code,
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
        routing_result = resolve_ai_provider_for_request(
            tenant_id=tenant_id,
            requested_provider=payload.provider,
            tenant_allowed_providers=set(ai_policy.allowed_providers),
            known_providers=known_provider_ids(),
            configured_providers=frozenset(
                provider_id
                for provider_id in configured_ai_providers()
                if provider_id in ai_policy.allowed_providers
            ),
            phi_detected=final_phi_classification.contains_phi,
            default_provider=ai_policy.default_provider,
            phi_provider=ai_policy.phi_provider,
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
                    "rag_source_chunk_ids": list(rag_context.source_chunk_ids),
                    "rag_retrieval_reason_code": rag_context.retrieval_reason_code,
                    "rag_query_phi_sensitivity": rag_context.query_phi_sensitivity,
                    "rag_max_sensitivity_level": rag_context.max_sensitivity_level,
                    "response_grounded": False,
                    "response_validation_result": None,
                    "response_validator_version": None,
                    "response_citation_source_ids": [],
                    "response_evidence_count": 0,
                    "policy_source": ai_policy.source,
                    "policy_version": ai_policy.version,
                    "policy_reason_code": ai_policy.reason_code,
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
                        ai_policy=ai_policy,
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
                    ai_policy=ai_policy,
                ),
            )
            self._record_violation(db, tenant_id, "AI_PROMPT_MINIMIZATION_FAILED")
            db.commit()
            raise ValueError("AI_PROMPT_MINIMIZATION_FAILED")

        prompt_sha = hashlib.sha256(outgoing_prompt.encode("utf-8")).hexdigest()
        request_id = f"inf-{prompt_sha[:16]}"

        prov_resp = None
        if not rag_context.rag_used:
            response_validation = validate_provider_response_grounding(
                response_text="",
                rag_context=rag_context,
                tenant_id=tenant_id,
            )
        else:
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
                        ai_policy=ai_policy,
                    ),
                )
                self._record_violation(db, tenant_id, exc.error_code)
                db.commit()
                raise ValueError(exc.error_code) from exc

            response_validation = validate_provider_response_grounding(
                response_text=prov_resp.text,
                rag_context=rag_context,
                tenant_id=tenant_id,
            )
            response_validation, _provenance_validation = validate_answer_provenance(
                response_text=prov_resp.text,
                rag_context=rag_context,
                response_validation=response_validation,
            )
        if prov_resp is None:
            response_validation, _provenance_validation = validate_answer_provenance(
                response_text="",
                rag_context=rag_context,
                response_validation=response_validation,
            )
        out = response_validation.final_text

        # Enforce require_grounded_response / no_answer_on_ungrounded only when an
        # operator has explicitly saved a DB retrieval policy. File-based defaults
        # use the existing NO_ANSWER return path and must not raise.
        if (
            _db_rag_rules is not None
            and effective_rag_rules.require_grounded_response
            and not response_validation.grounded
            and effective_rag_rules.no_answer_on_ungrounded
        ):
            self._record_violation(db, tenant_id, "RETRIEVAL_POLICY_GROUNDING_REQUIRED")
            db.commit()
            raise ValueError("RETRIEVAL_POLICY_GROUNDING_REQUIRED")

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
                "model_id": prov_resp.model
                if prov_resp is not None
                else effective_provider,
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
                response_text=out,
                provider_response=prov_resp,
                prompt_minimization=prompt_minimization,
                request_id=request_id,
                routing_result=routing_result,
                rag_context=rag_context,
                response_validation=response_validation,
                ai_policy=ai_policy,
            ),
        )
        evidence_response = _build_evidence_aware_response(
            answer=out,
            rag_context=rag_context,
            response_validation=response_validation,
            compliance_mode=compliance_mode,
            retrieval_policy_applied=_db_rag_rules is not None,
            effective_rag_rules=effective_rag_rules,
            policy_version=int(_stored_retrieval_policy["policy_version"])
            if _stored_retrieval_policy is not None
            else ai_policy.version,
        )

        return {
            "ok": True,
            "provider": effective_provider,
            "model": prov_resp.model if prov_resp is not None else effective_provider,
            "response": out,
            "answer": evidence_response["answer"],
            "evidence": evidence_response["evidence"],
            "inference": evidence_response["inference"],
            "uncertainty": evidence_response["uncertainty"],
            "risk_score": evidence_response["risk_score"],
            "requires_human_review": evidence_response["requires_human_review"],
            "sources": _chat_sources(response_validation),
            "confidence": _chat_confidence(response_validation),
            "metadata": _rag_answer_metadata(rag_context),
            "provenance": {
                **_rag_provenance_ui_metadata(rag_context, response_validation),
                "retrieval_policy_applied": _db_rag_rules is not None,
                "grounded_required": effective_rag_rules.require_grounded_response,
                "no_answer_on_ungrounded": effective_rag_rules.no_answer_on_ungrounded,
                "rag_enabled": effective_rag_rules.enabled,
            },
            "evidence_response": evidence_response,
            "simulated": effective_provider == "simulated",
        }

    def chat(
        self, db: Session, tenant_id: str, payload: AIChatRequest
    ) -> dict[str, object]:
        result = self.infer(
            db,
            tenant_id,
            AIInferRequest(query=payload.message, provider=payload.provider),
        )
        raw_sources = result.get("sources")
        sources = (
            cast(list[dict[str, str]], raw_sources)
            if isinstance(raw_sources, list)
            else []
        )
        raw_confidence = result.get("confidence")
        confidence = (
            float(raw_confidence)
            if isinstance(raw_confidence, int | float)
            and not isinstance(raw_confidence, bool)
            else 0.0
        )
        return {
            "answer": str(result.get("response") or ""),
            "sources": sources,
            "confidence": confidence,
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
