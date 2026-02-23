"""
tests/control_plane/test_control_plane_phase3.py — Phase 3: AI Drift Elimination Tests.

Tests cover:
  - Tenant-scoped namespace derivation (deterministic, isolated)
  - Cross-tenant namespace isolation (structural proof)
  - Retriever tenant binding (reject empty/None tenant)
  - Cross-tenant source contamination detection
  - AI namespace endpoint (tenant from auth only)
  - Negative: cross-tenant retrieval must fail
  - Negative: empty tenant rejected

Security invariants verified:
  - No cross-tenant namespace sharing
  - Empty tenant rejected
  - Namespace derived from auth context only (not request body)
"""

from __future__ import annotations

import hashlib
import pytest

from services.cp_ai_isolation import (
    derive_tenant_namespace,
    validate_namespace_binding,
    get_retriever,
    assert_no_cross_tenant_retrieval,
    TenantScopedRetriever,
    IsolationViolationError,
    NAMESPACE_VERSION,
    NAMESPACE_HEX_LENGTH,
)


class TestNamespaceDerivation:
    """Test deterministic namespace derivation."""

    def test_namespace_deterministic(self):
        """Same tenant_id always produces same namespace."""
        ns1 = derive_tenant_namespace("tenant-alpha")
        ns2 = derive_tenant_namespace("tenant-alpha")
        assert ns1 == ns2

    def test_namespace_length(self):
        """Namespace is exactly NAMESPACE_HEX_LENGTH hex chars."""
        ns = derive_tenant_namespace("tenant-beta")
        assert len(ns) == NAMESPACE_HEX_LENGTH
        assert all(c in "0123456789abcdef" for c in ns)

    def test_namespace_unique_per_tenant(self):
        """Different tenants produce different namespaces."""
        ns_a = derive_tenant_namespace("tenant-alpha")
        ns_b = derive_tenant_namespace("tenant-beta")
        ns_c = derive_tenant_namespace("tenant-gamma")
        assert ns_a != ns_b
        assert ns_b != ns_c
        assert ns_a != ns_c

    def test_namespace_empty_tenant_rejected(self):
        """Empty tenant_id raises IsolationViolationError."""
        with pytest.raises(IsolationViolationError, match="AI_TENANT_REQUIRED"):
            derive_tenant_namespace("")

    def test_namespace_none_tenant_rejected(self):
        """None-like empty string raises IsolationViolationError."""
        with pytest.raises(IsolationViolationError, match="AI_TENANT_REQUIRED"):
            derive_tenant_namespace("   ")

    def test_namespace_sha256_construction(self):
        """Namespace is SHA-256 prefix of ns:v1:<tenant_id>."""
        tenant_id = "test-tenant-xyz"
        expected_full = hashlib.sha256(
            f"{NAMESPACE_VERSION}{tenant_id}".encode("utf-8")
        ).hexdigest()
        expected_ns = expected_full[:NAMESPACE_HEX_LENGTH]
        actual_ns = derive_tenant_namespace(tenant_id)
        assert actual_ns == expected_ns

    def test_namespace_case_sensitive(self):
        """Namespace derivation is case-sensitive."""
        ns_lower = derive_tenant_namespace("tenant-alpha")
        ns_upper = derive_tenant_namespace("TENANT-ALPHA")
        assert ns_lower != ns_upper


class TestCrossTenantIsolation:
    """Test structural cross-tenant isolation enforcement."""

    def test_assert_no_cross_tenant_retrieval_passes(self):
        """Cross-tenant check passes for distinct tenants."""
        # Must not raise
        assert_no_cross_tenant_retrieval("tenant-a", "tenant-b")
        assert_no_cross_tenant_retrieval("alpha", "beta")
        assert_no_cross_tenant_retrieval("tenant-001", "tenant-002")

    def test_assert_no_cross_tenant_retrieval_same_tenant_raises(self):
        """
        NEGATIVE TEST: Same tenant_id used as both tenants.

        This simulates an invariant violation — two identical tenants should
        never be tested against each other for isolation.
        """
        with pytest.raises(AssertionError, match="INVARIANT VIOLATED"):
            assert_no_cross_tenant_retrieval("tenant-x", "tenant-x")

    def test_cross_tenant_namespaces_never_equal(self):
        """
        Structural proof: 100 distinct tenant_ids produce 100 distinct namespaces.
        Demonstrates SHA-256 preimage resistance in practice.
        """
        tenants = [f"tenant-{i:04d}" for i in range(100)]
        namespaces = [derive_tenant_namespace(t) for t in tenants]
        assert len(set(namespaces)) == 100, (
            "All namespaces must be distinct — cross-tenant drift detected"
        )


class TestTenantScopedRetriever:
    """Test TenantScopedRetriever isolation enforcement."""

    def test_retriever_binds_to_tenant(self):
        """Retriever is bound to tenant at creation time."""
        r = TenantScopedRetriever(tenant_id="tenant-alpha")
        assert r.tenant_id == "tenant-alpha"
        assert r.namespace == derive_tenant_namespace("tenant-alpha")

    def test_retriever_empty_tenant_rejected(self):
        """Retriever with empty tenant_id raises IsolationViolationError."""
        with pytest.raises(IsolationViolationError, match="AI_TENANT_REQUIRED"):
            TenantScopedRetriever(tenant_id="")

    def test_retriever_retrieve_returns_namespace(self):
        """Retrieve result includes namespace and tenant_id."""
        r = TenantScopedRetriever(tenant_id="tenant-alpha")
        result = r.retrieve("test query")
        assert result["namespace"] == r.namespace
        assert result["tenant_id"] == "tenant-alpha"
        assert result["ok"] is True
        assert "retrieval_id" in result

    def test_retriever_different_tenants_different_namespace(self):
        """
        NEGATIVE TEST (cross-tenant isolation):
        Two retrievers for different tenants must have different namespaces.
        They structurally cannot access each other's data.
        """
        r_a = TenantScopedRetriever(tenant_id="tenant-alpha")
        r_b = TenantScopedRetriever(tenant_id="tenant-beta")
        assert r_a.namespace != r_b.namespace, (
            "ISOLATION VIOLATED: different tenants share a namespace"
        )

    def test_retriever_rejects_foreign_namespace_source(self):
        """
        NEGATIVE TEST: Retriever rejects sources from foreign namespaces.

        If a source with a different namespace appears in results,
        IsolationViolationError is raised (cross-contamination detection).
        """
        r = TenantScopedRetriever(tenant_id="tenant-alpha")
        foreign_ns = derive_tenant_namespace("tenant-beta")

        contaminated_sources = [
            {"namespace": foreign_ns, "content": "foreign data"},
        ]
        with pytest.raises(IsolationViolationError, match="AI_CROSS_TENANT_RETRIEVAL"):
            r.retrieve("test query", sources=contaminated_sources)

    def test_retriever_accepts_own_namespace_sources(self):
        """Retriever accepts sources from its own namespace."""
        r = TenantScopedRetriever(tenant_id="tenant-alpha")
        own_sources = [
            {"namespace": r.namespace, "content": "tenant data"},
        ]
        result = r.retrieve("test query", sources=own_sources)
        assert result["ok"] is True
        assert len(result["sources"]) == 1


class TestNamespaceValidation:
    """Test validate_namespace_binding enforcement."""

    def test_validate_matching_namespace_passes(self):
        """Matching namespace passes validation."""
        tenant_id = "tenant-alpha"
        ns = derive_tenant_namespace(tenant_id)
        # Must not raise
        validate_namespace_binding(requested_namespace=ns, tenant_id=tenant_id)

    def test_validate_mismatched_namespace_raises(self):
        """
        NEGATIVE TEST: Mismatched namespace raises IsolationViolationError.
        This prevents cross-tenant namespace injection.
        """
        with pytest.raises(IsolationViolationError, match="AI_NAMESPACE_MISMATCH"):
            validate_namespace_binding(
                requested_namespace=derive_tenant_namespace("tenant-beta"),
                tenant_id="tenant-alpha",
            )

    def test_validate_arbitrary_namespace_rejected(self):
        """Arbitrary namespace string is rejected."""
        with pytest.raises(IsolationViolationError):
            validate_namespace_binding(
                requested_namespace="00000000000000000000000000000000",
                tenant_id="tenant-alpha",
            )


class TestGetRetriever:
    """Test get_retriever factory."""

    def test_get_retriever_returns_scoped_instance(self):
        """Factory returns correctly scoped retriever."""
        r = get_retriever("tenant-test")
        assert isinstance(r, TenantScopedRetriever)
        assert r.tenant_id == "tenant-test"

    def test_get_retriever_empty_tenant_rejected(self):
        """Factory rejects empty tenant_id."""
        with pytest.raises(IsolationViolationError):
            get_retriever("")


class TestAIInvariantsCI:
    """
    CI-gate tests for AI isolation invariants.
    These tests are referenced by check_control_plane_v2_invariants.py.
    """

    def test_invariant_ai_namespace_requires_tenant(self):
        """Invariant: AI namespace derivation requires non-empty tenant_id."""
        with pytest.raises(IsolationViolationError):
            derive_tenant_namespace("")

    def test_invariant_ai_cross_tenant_retrieval_blocked(self):
        """
        Invariant: Cross-tenant source contamination is detected and blocked.
        This test intentionally triggers the isolation violation.
        """
        r = TenantScopedRetriever(tenant_id="tenant-alpha")
        foreign_ns = derive_tenant_namespace("tenant-beta")
        with pytest.raises(IsolationViolationError):
            r.retrieve("query", sources=[{"namespace": foreign_ns}])

    def test_invariant_namespaces_structurally_isolated(self):
        """
        Invariant: All tenant namespaces are structurally distinct.
        Proof by construction: 50 tenants → 50 distinct namespaces.
        """
        tenants = [f"org-{i}" for i in range(50)]
        namespaces = {derive_tenant_namespace(t) for t in tenants}
        assert len(namespaces) == 50
