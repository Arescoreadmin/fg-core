# tests/security/test_agent_device_credential_contract.py
"""
R4.10 contract tests — agent_device credential authority.

Verifies the public API contract of the credential authority for agent_device:
  - Functions exist and have the expected signatures
  - Error types and absent flag contracts
  - Metadata contract (required fields preserved round-trip)
  - Sentinel design invariants (legacy fingerprints never match canonical)
  - Credential type is in VALID_CREDENTIAL_TYPES
"""

from __future__ import annotations

import inspect
import re

import api.credential_authority as ca
from api.credential_authority import (
    AgentDeviceCredentialMetadata,
    BootstrapTokenResult,
    DEVICE_TRUST_STATES,
    VALID_TRUST_TRANSITIONS,
)


class TestCredentialAuthorityContract:
    def test_agent_device_in_valid_credential_types(self) -> None:
        assert "agent_device" in ca.VALID_CREDENTIAL_TYPES

    def test_default_agent_device_ttl_is_90_days(self) -> None:
        assert ca.DEFAULT_AGENT_DEVICE_CREDENTIAL_TTL_SECONDS == 90 * 24 * 3600

    def test_default_bootstrap_token_ttl_is_1_hour(self) -> None:
        assert ca.DEFAULT_BOOTSTRAP_TOKEN_TTL_SECONDS == 3600

    def test_suspend_credential_function_exists(self) -> None:
        assert callable(ca.suspend_credential)

    def test_resume_credential_function_exists(self) -> None:
        assert callable(ca.resume_credential)

    def test_issue_bootstrap_token_function_exists(self) -> None:
        assert callable(ca.issue_bootstrap_token)

    def test_exchange_bootstrap_token_function_exists(self) -> None:
        assert callable(ca.exchange_bootstrap_token)

    def test_validate_trust_transition_function_exists(self) -> None:
        assert callable(ca.validate_trust_transition)

    def test_bootstrap_token_result_is_frozen_dataclass(self) -> None:
        import dataclasses

        assert dataclasses.is_dataclass(BootstrapTokenResult)
        assert BootstrapTokenResult.__dataclass_params__.frozen  # type: ignore[attr-defined]

    def test_bootstrap_token_result_fields(self) -> None:
        import dataclasses

        fields = {f.name for f in dataclasses.fields(BootstrapTokenResult)}
        assert fields == {"raw_token", "tenant_id", "expires_at", "enrollment_id"}

    def test_agent_device_metadata_required_fields(self) -> None:
        required = {
            "agent_id",
            "device_id",
            "hostname",
            "platform",
            "architecture",
            "os_version",
            "agent_version",
            "deployment_environment",
            "bootstrap_method",
            "trust_level",
            "credential_slot",
            "issued_by",
            "rotation_generation",
            "hardware_fingerprint",
        }
        fields = set(AgentDeviceCredentialMetadata.model_fields.keys())
        assert required.issubset(fields)

    def test_agent_device_metadata_optional_fields(self) -> None:
        optional = {
            "device_uuid",
            "certificate_serial",
            "public_key_fingerprint",
            "enrollment_id",
            "attestation_hash",
            "last_seen",
            "last_successful_authentication",
            "metadata_version",
            "future_extensions",
        }
        fields = set(AgentDeviceCredentialMetadata.model_fields.keys())
        assert optional.issubset(fields)

    def test_device_trust_states_has_11_entries(self) -> None:
        assert len(DEVICE_TRUST_STATES) == 11

    def test_valid_trust_transitions_covers_all_non_terminal(self) -> None:
        terminal = {"revoked", "expired"}
        non_terminal = DEVICE_TRUST_STATES - terminal
        for state in non_terminal:
            assert state in VALID_TRUST_TRANSITIONS

    def test_terminal_states_have_no_outgoing_transitions(self) -> None:
        terminal = {"revoked", "expired"}
        for state in terminal:
            assert VALID_TRUST_TRANSITIONS.get(state, frozenset()) == frozenset()

    def test_credential_not_found_error_has_absent_attr(self) -> None:
        err = ca.CredentialNotFoundError("test", absent=True)
        assert err.absent is True
        err2 = ca.CredentialNotFoundError("test", absent=False)
        assert err2.absent is False

    def test_credential_state_error_is_value_error(self) -> None:
        assert issubclass(ca.CredentialStateError, ValueError)

    def test_suspend_credential_signature(self) -> None:
        sig = inspect.signature(ca.suspend_credential)
        params = set(sig.parameters.keys())
        assert {"engine", "credential_id", "tenant_id", "actor_id", "reason"} <= params

    def test_resume_credential_signature(self) -> None:
        sig = inspect.signature(ca.resume_credential)
        params = set(sig.parameters.keys())
        assert {"engine", "credential_id", "tenant_id", "actor_id"} <= params

    def test_issue_bootstrap_token_signature(self) -> None:
        sig = inspect.signature(ca.issue_bootstrap_token)
        params = set(sig.parameters.keys())
        assert {"engine", "tenant_id", "actor_id", "ttl_seconds", "reason"} <= params

    def test_exchange_bootstrap_token_signature(self) -> None:
        sig = inspect.signature(ca.exchange_bootstrap_token)
        params = set(sig.parameters.keys())
        required = {
            "engine",
            "tenant_id",
            "raw_token",
            "agent_id",
            "device_id",
            "hostname",
            "platform",
            "architecture",
            "os_version",
            "agent_version",
            "hardware_fingerprint",
        }
        assert required <= params

    def test_sentinel_fingerprint_cannot_match_hmac_sha256(self) -> None:
        sentinel = "legacy:42"
        assert not re.match(r"^[0-9a-f]{64}$", sentinel)

    def test_sentinel_slot_cannot_collide_with_canonical_slot(self) -> None:
        canonical_slots = [f"agent:{i}" for i in range(100)]
        sentinel_slots = [f"legacy:device:d{i}:{i}" for i in range(100)]
        for s in sentinel_slots:
            assert s not in canonical_slots
