from __future__ import annotations

import hashlib

from services.ai.providers.base import ProviderResponse
from services.ai.routing import AiProviderRoutingResult
from services.phi_classifier.minimizer import PromptMinimizationResult
from services.provider_baa.gate import BaaGateResult


def _sha256_text(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _safe_phi_types(baa_gate_result: BaaGateResult) -> list[str]:
    return sorted(baa_gate_result.phi_types - {"medical_keyword"})


def build_ai_audit_metadata(
    *,
    tenant_id: str,
    provider_id: str,
    baa_gate_result: BaaGateResult,
    request_text: str,
    response_text: str | None = None,
    provider_response: ProviderResponse | None = None,
    prompt_minimization: PromptMinimizationResult | None = None,
    request_hash: str | None = None,
    request_id: str | None = None,
    device_id: str | None = None,
    routing_result: AiProviderRoutingResult | None = None,
) -> dict[str, object]:
    """Build safe AI audit metadata with hashes only for request/response text."""
    effective_response_text = (
        provider_response.text if provider_response is not None else response_text
    )
    metadata: dict[str, object] = {
        "phi_detected": bool(baa_gate_result.contains_phi),
        "phi_types": _safe_phi_types(baa_gate_result),
        "provider_id": provider_response.provider_id
        if provider_response is not None
        else provider_id,
        "baa_check_result": baa_gate_result.enforcement_action,
        "request_hash": request_hash or _sha256_text(request_text),
        "response_hash": _sha256_text(effective_response_text)
        if effective_response_text is not None
        else None,
        "tenant_id": tenant_id,
        "enforcement_action": baa_gate_result.enforcement_action,
        "reason_code": baa_gate_result.reason_code,
        "sensitivity_level": baa_gate_result.sensitivity_level.value,
        "prompt_minimized": bool(
            prompt_minimization.changed if prompt_minimization is not None else False
        ),
        "minimization_version": prompt_minimization.minimization_version
        if prompt_minimization is not None
        else None,
        "minimization_replacement_count": prompt_minimization.replacement_count
        if prompt_minimization is not None
        else 0,
        "minimization_placeholder_types": prompt_minimization.placeholder_types
        if prompt_minimization is not None
        else [],
    }
    if request_id:
        metadata["request_id"] = request_id
    if device_id:
        metadata["device_id"] = device_id
    if routing_result is not None:
        metadata["requested_provider"] = routing_result.requested_provider
        metadata["selected_by"] = routing_result.selected_by
        metadata["routing_reason_code"] = routing_result.reason_code
        metadata["requires_baa"] = routing_result.requires_baa
    if provider_response is not None:
        metadata["model"] = provider_response.model
        if provider_response.input_tokens is not None:
            metadata["input_tokens"] = provider_response.input_tokens
        if provider_response.output_tokens is not None:
            metadata["output_tokens"] = provider_response.output_tokens
    return metadata
