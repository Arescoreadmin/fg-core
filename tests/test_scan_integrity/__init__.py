"""
Test suite for L14-SCAN-INTEGRITY-001 — canonical scanner evidence integrity
and finding confidence enforcement.

Modules
-------
test_canonicalization  — deterministic payload hashing
test_provenance        — ProvenanceStatus enforcement
test_confidence        — FindingConfidence classification rules
test_custody           — chain-of-custody event recording
test_isolation         — tenant isolation invariants

NOT_STANDALONE: These tests exercise the FrostGate Core field assessment
pipeline.  They require the full fg-core stack (api/, services/, Postgres
schema 0201 for DB tests; SQLite for unit tests).

---

AUTH-GAP-001: Customer authorization provenance gap
  Status: OPEN — follow-up PR L14-SCAN-CONSENT-001 required
  Existing: operator-managed scan authorization (fa_scan_authorizations,
            migration 0200, L14-SCAN-SAFETY-001)
  Missing: independently authenticated client consent receipt for all
           scanner types. The current authorization model is operator-to-
           operator; there is no signed client consent receipt that binds
           scope, tenant, engagement, scanner types, and timestamp in a
           form the client can independently verify.
  Required: signed client receipt binding scope, tenant, engagement,
            scanner types, and timestamp. The receipt must be:
            (a) signed by FrostGate with a client-verifiable key
            (b) stored in fa_scan_evidence_envelopes.authorization_ref
            (c) verifiable offline by the client using the public key only
  Fail-closed requirement: scanner dispatch without a valid client consent
            receipt MUST record provenance_status=UNVERIFIED (not CONFIRMED).
            This is currently enforced at the service layer; the receipt
            itself is not yet implemented.
  Owning PR: L14-SCAN-CONSENT-001 (follow-up, not in this PR)

AUTH-GAP-002: Background execution revalidation gap
  Status: OPEN — follow-up PR L14-SCAN-AUTHZ-HARDENING-001 required
  Existing: route-level authorization check at dispatch time via
            check_scan_authorized() in services/field_assessment/scan_authorization.py
            (L14-SCAN-SAFETY-001, PR #809)
  Missing: re-validation of authorization at worker execution start.
           A scan job is dispatched and queued. If the authorization record
           is revoked or expires between dispatch and execution, the worker
           proceeds with the original authorization check result (stale).
  Risk: authorization may expire or be revoked between dispatch and
        execution (e.g., client revokes consent during a long queue). The
        worker has no mechanism to re-check the authorization at execution
        start time.
  FVA-01 status: PARTIALLY_IMPLEMENTED until execution-time revalidation
        is proven. The scope boundary is enforced at dispatch; it is NOT
        enforced at execution. This is the remaining gap in FVA-01.
  Owning PR: L14-SCAN-AUTHZ-HARDENING-001 (follow-up, not in this PR)
"""
