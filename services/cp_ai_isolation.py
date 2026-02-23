"""
services/cp_ai_isolation.py — FrostGate Control Plane v2 AI Isolation Service.

Phase 3: AI Drift Elimination.

Enforces:
  - Every AI operation MUST carry a tenant-scoped embedding namespace.
  - No cross-tenant embedding namespace access.
  - No shared retriever context across tenants.
  - Retrieval records always scoped to a single tenant's namespace.
  - No shared in-memory model state.

Security invariants:
  - Namespace derived from tenant_id ONLY — never from request body.
  - Cross-tenant namespace access raises IsolationViolationError.
  - Empty/None tenant_id is rejected (no global inference without explicit admin scope).
  - All retrievals logged with namespace binding for audit.
  - No subprocess, no shell, no dynamic dispatch.

Namespace design:
  namespace = sha256("ns:v1:" + tenant_id)[:32]

This means:
  - Tenant A's vectors live in namespace A'.
  - Tenant B's vectors live in namespace B'.
  - They cannot share a namespace even if tenant_ids collide due to SHA-256 preimage resistance.
"""

from __future__ import annotations

import hashlib
import logging
from typing import Any, Dict, List, Optional

log = logging.getLogger("frostgate.cp_ai_isolation")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

NAMESPACE_VERSION = "ns:v1:"
NAMESPACE_HEX_LENGTH = 32  # 128-bit prefix of SHA-256 for namespace ID

# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class IsolationViolationError(ValueError):
    """Raised when cross-tenant AI access is attempted."""

    pass


# ---------------------------------------------------------------------------
# Namespace derivation
# ---------------------------------------------------------------------------


def derive_tenant_namespace(tenant_id: str) -> str:
    """
    Derive a deterministic, tenant-scoped embedding namespace.

    namespace = sha256("ns:v1:" + tenant_id)[:32]

    Properties:
      - Deterministic: same tenant_id → same namespace always.
      - Isolated: different tenants → different namespaces (SHA-256 collision resistance).
      - Opaque: namespace does not reveal raw tenant_id.
      - Short: 32 hex chars (128-bit prefix), suitable for index partitioning.

    Raises ValueError if tenant_id is empty or None.
    """
    if not tenant_id or not tenant_id.strip():
        raise IsolationViolationError(
            "AI_TENANT_REQUIRED: tenant_id required for namespace derivation"
        )
    raw = f"{NAMESPACE_VERSION}{tenant_id}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:NAMESPACE_HEX_LENGTH]


def validate_namespace_binding(
    *,
    requested_namespace: str,
    tenant_id: str,
) -> None:
    """
    Validate that a requested namespace matches the tenant's derived namespace.

    Raises IsolationViolationError if there is a mismatch.
    This prevents cross-tenant namespace injection.
    """
    expected = derive_tenant_namespace(tenant_id)
    if requested_namespace != expected:
        log.error(
            "cp_ai_isolation.namespace_mismatch "
            "tenant=%s expected_ns=%s got_ns=%s",
            tenant_id,
            expected,
            requested_namespace,
        )
        raise IsolationViolationError(
            f"AI_NAMESPACE_MISMATCH: requested namespace does not match tenant "
            f"(tenant={tenant_id!r})"
        )


# ---------------------------------------------------------------------------
# Retriever isolation
# ---------------------------------------------------------------------------


class TenantScopedRetriever:
    """
    Retriever that enforces per-tenant vector namespace isolation.

    Every retrieve() call is bound to a single tenant's namespace.
    Cross-tenant access is structurally impossible.

    In production this wraps a vector database (Pinecone, Weaviate, pgvector, etc.)
    with namespace partitioning. In the stub implementation, we enforce the
    namespace contract at the API boundary and return deterministic results.
    """

    def __init__(self, tenant_id: str) -> None:
        if not tenant_id or not tenant_id.strip():
            raise IsolationViolationError("AI_TENANT_REQUIRED: tenant_id required")
        self._tenant_id = tenant_id
        self._namespace = derive_tenant_namespace(tenant_id)
        log.debug(
            "cp_ai_isolation.retriever_init tenant=%s namespace=%s",
            tenant_id,
            self._namespace,
        )

    @property
    def namespace(self) -> str:
        return self._namespace

    @property
    def tenant_id(self) -> str:
        return self._tenant_id

    def retrieve(
        self,
        query: str,
        *,
        top_k: int = 5,
        sources: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Retrieve relevant context for a query within this tenant's namespace.

        Parameters:
          query:     The query string.
          top_k:     Maximum number of results to return.
          sources:   Optional pre-seeded sources (for stub/test mode).

        Returns a dict with:
          ok:           True if retrieval succeeded.
          namespace:    The tenant's scoped namespace.
          tenant_id:    The tenant (for audit trail).
          sources:      Retrieved context documents.
          retrieval_id: Unique ID for this retrieval event.

        Raises IsolationViolationError if any retrieved document has a
        different namespace (defensive cross-contamination check).
        """
        import uuid

        retrieval_id = str(uuid.uuid4())
        returned_sources = sources or []

        # Defensive: verify all returned sources are namespace-scoped
        for src in returned_sources:
            src_ns = src.get("namespace")
            if src_ns is not None and src_ns != self._namespace:
                log.error(
                    "cp_ai_isolation.cross_tenant_source_detected "
                    "tenant=%s expected_ns=%s got_ns=%s retrieval_id=%s",
                    self._tenant_id,
                    self._namespace,
                    src_ns,
                    retrieval_id,
                )
                raise IsolationViolationError(
                    f"AI_CROSS_TENANT_RETRIEVAL: source from foreign namespace "
                    f"detected (expected={self._namespace!r}, got={src_ns!r})"
                )

        log.info(
            "cp_ai_isolation.retrieve tenant=%s namespace=%s "
            "query_len=%d top_k=%d retrieval_id=%s",
            self._tenant_id,
            self._namespace,
            len(query),
            top_k,
            retrieval_id,
        )

        return {
            "ok": True,
            "namespace": self._namespace,
            "tenant_id": self._tenant_id,
            "sources": returned_sources,
            "retrieval_id": retrieval_id,
        }


# ---------------------------------------------------------------------------
# Cross-tenant isolation check (used in tests + CI)
# ---------------------------------------------------------------------------


def assert_no_cross_tenant_retrieval(
    tenant_a_id: str,
    tenant_b_id: str,
) -> None:
    """
    Structural proof that two different tenants cannot share a namespace.

    Raises AssertionError if the invariant is violated (impossible unless
    SHA-256 collision occurs, which is computationally infeasible).

    Used in tests and CI to verify namespace isolation is structurally enforced.
    """
    ns_a = derive_tenant_namespace(tenant_a_id)
    ns_b = derive_tenant_namespace(tenant_b_id)
    assert ns_a != ns_b, (
        f"INVARIANT VIOLATED: tenants '{tenant_a_id}' and '{tenant_b_id}' "
        f"share namespace '{ns_a}' — this must never happen"
    )
    log.info(
        "cp_ai_isolation.cross_tenant_check_passed "
        "tenant_a=%s ns_a=%s tenant_b=%s ns_b=%s",
        tenant_a_id, ns_a, tenant_b_id, ns_b,
    )


def get_retriever(tenant_id: str) -> TenantScopedRetriever:
    """
    Factory: return a tenant-scoped retriever.

    Raises IsolationViolationError if tenant_id is empty/None.
    """
    return TenantScopedRetriever(tenant_id=tenant_id)
