# L14 Scanner Evidence Integrity

**Document ID:** L14-SCAN-INTEGRITY-001
**Version:** 1.0
**Date:** 2026-11-07
**Status:** IMPLEMENTED — digest-only integrity (VERIFIED_INTEGRITY_ONLY); Vault Transit NOT_WIRED for scanner receipts
**Owning PR:** feat/l14-scan-integrity-001

---

## 1. Evidence Authority Map

Scanner evidence flows through the following authority chain:

```
Scanner runner
    → raw payload (dict)
    → canonicalize_payload()           (services/field_assessment/evidence_integrity.py)
    → compute_payload_digest()         → "sha256:<hex>"
    → ScannerEvidenceEnvelope          (dataclass, in-memory)
    → fa_scan_evidence_envelopes       (Postgres, migration 0201)
    → EvidenceCustodyService.record()  → fa_evidence_custody_events
    → FaNormalizedFinding.confidence_level (migration 0201 ALTER)
    → Report generation (L14-SCAN-REPORT-PROOF-001, future)
```

Authority services:

| Service | File | Responsibility |
|---------|------|---------------|
| EvidenceIntegrityService | services/field_assessment/evidence_integrity.py | Build envelopes, verify digests |
| EvidenceCustodyService | services/field_assessment/custody.py | Record/retrieve custody events |
| FindingConfidence | services/field_assessment/finding_confidence.py | Classify confidence from evidence quality |

---

## 2. Payload Canonicalization Rules

Canonicalization ensures that two structurally equivalent payloads always produce the same digest regardless of Python dict insertion order, unicode form, or encoder behavior.

**Algorithm (canonicalization version 1.0):**

1. Apply NFC unicode normalization recursively to all string keys and values
2. Sort dict keys recursively (all nesting levels)
3. Retain explicit null values (not stripped)
4. Wrap in a version envelope: `{"__meta__": {"canonicalization_version": "1.0", "schema_version": "<version>"}, "payload": <sorted_payload>}`
5. Serialize with `json.dumps(separators=(',', ':'), ensure_ascii=False, sort_keys=True)`
6. Encode as UTF-8 bytes

**Stability guarantees:**

- Same dict + same schema_version → same bytes (deterministic)
- Different key insertion order → same bytes (key-sorted)
- NFC vs NFD unicode → same bytes (NFC-normalized before serialization)
- `None` values retained → different from omitted keys
- schema_version 1.0 vs 1.1 → different bytes (version-scoped)

---

## 3. Digest Semantics

**Format:** `"sha256:<64-char lowercase hex>"`

The `sha256:` prefix is mandatory. It makes the algorithm self-describing in stored records. Callers MUST NOT store bare hex values.

**Example:**

```python
compute_payload_digest({"host": "example.com", "port": 443})
# → "sha256:a1b2c3...64 chars..."
```

**Versioning:** Each canonicalization version produces a distinct digest space. If the canonicalization algorithm changes, a new `canonicalization_version` ("1.1", "2.0") is introduced. Legacy records retain their original digest without re-hashing.

**Storage column:** `fa_scan_evidence_envelopes.payload_digest TEXT NOT NULL`

---

## 4. Signature Semantics

**Current status: NOT_IMPLEMENTED for scanner receipts.**

Vault Transit exists in this repo (`services/field_assessment/auditor_proof_authority.py`) but is scoped to delivery-artifact signing (Ed25519 proof packages). Scanner receipt signing requires a dedicated Vault Transit key provisioned under a future PR.

**Current behavior:**
- `EvidenceIntegrityService._try_vault_sign()` always returns `(None, None)`
- `signature_ref` is always `None` on built envelopes
- `provenance_status` defaults to `VERIFIED_INTEGRITY_ONLY` (digest matches, no authenticated signature)

**When Vault Transit is wired (L14-SCAN-VAULT-001):**
- `_try_vault_sign()` calls the Vault Transit API with the envelope digest bytes
- Returns `(signature_bytes, key_ref)` where `key_ref` is the Vault key path
- `signature_ref` is stored; `provenance_status` becomes `VERIFIED_AUTHENTIC`

**Signatures are NEVER fabricated.** If Vault is unavailable, the envelope records `signature_ref=None` and `provenance_status=VERIFIED_INTEGRITY_ONLY`. There is no fallback to a weaker or simulated signature.

---

## 5. Verification State Model

Six `ProvenanceStatus` values are defined:

| Status | Meaning | Conditions |
|--------|---------|------------|
| `VERIFIED_AUTHENTIC` | Digest matches AND authenticated Vault signature present | Future: Vault Transit wired |
| `VERIFIED_INTEGRITY_ONLY` | Digest matches; no authenticated signature | Current default for successful builds |
| `UNVERIFIED` | Envelope exists; integrity not yet checked | Legacy or unprocessed records |
| `MISSING` | Record not found, or cross-tenant access attempted | DB returns no row, or tenant mismatch |
| `INVALID` | Digest or signature verification failed | Payload was mutated or corrupted |
| `INDETERMINATE` | Verification service could not conclude | DB error, internal exception |

**Fail-closed semantics:**
- `MISSING` is returned for both "not found" and "cross-tenant" (prevents information leakage)
- `INDETERMINATE` is returned for internal errors (never silently passes)
- `INVALID` is returned immediately on any digest mismatch (never degrades silently)

---

## 6. Confidence Classification Rules

Confidence and severity are independent dimensions (Rule 3.5 of FROSTGATE_FINDING_CONFIDENCE_POLICY.md).

| Rule | Input conditions | Output |
|------|-----------------|--------|
| C-1 | `evidence_present=False` | `UNKNOWN` |
| C-2 | `provenance_status` in `{INVALID, MISSING}` | max `SUSPECTED` |
| C-3 | `verification_method=INTERVIEW_ASSERTION` | max `PROBABLE` |
| C-4 | `verification_method=INFERENCE` | max `SUSPECTED` |
| C-5 | `collection_complete=False` | max `PROBABLE` |
| C-6 | Authoritative method + complete + VERIFIED_* | `CONFIRMED` allowed |
| C-7 | Authoritative method + unverified provenance | `PROBABLE` |
| C-8 | `NOT_VERIFIED` method | `SUSPECTED` |
| C-8b | `DOCUMENT_REVIEW` or `INDEPENDENT_CORROBORATION` | `PROBABLE` |

Stricter rules take precedence. Example: `INTERVIEW_ASSERTION + collection_complete=False` → Rule C-3 applies (max `PROBABLE`), not escalated by C-5.

---

## 7. Verification Method Contract

| Method | Supports CONFIRMED | Notes |
|--------|-------------------|-------|
| `DIRECT_TECHNICAL_OBSERVATION` | Yes | Live technical request + response |
| `AUTHORITATIVE_CONFIGURATION_EXPORT` | Yes | Config from authoritative source |
| `INDEPENDENT_CORROBORATION` | No (alone) | Second source confirms same finding |
| `DOCUMENT_REVIEW` | No | Documents may be outdated |
| `INTERVIEW_ASSERTION` | No | Weakest; must be corroborated |
| `INFERENCE` | No | Logical deduction; no direct observation |
| `NOT_VERIFIED` | No | Scanner-generated, no secondary verification |

---

## 8. Scanner Adapter Coverage Matrix

| Scanner | Envelope | Digest | Confidence | Custody | Notes |
|---------|----------|--------|------------|---------|-------|
| network_scan | Supported | Supported | DIRECT_TECHNICAL_OBSERVATION | Supported | Strong existing provenance |
| dns_email | Supported | Supported | DIRECT_TECHNICAL_OBSERVATION | Supported | PARTIAL runner fields — L14-SCAN-COMPLETENESS-001 follow-up |
| web_headers | Supported | Supported | DIRECT_TECHNICAL_OBSERVATION | Supported | PARTIAL runner fields — L14-SCAN-COMPLETENESS-001 follow-up |
| microsoft_graph | FOLLOW_UP_REQUIRED | FOLLOW_UP_REQUIRED | AUTHORITATIVE_CONFIGURATION_EXPORT | FOLLOW_UP_REQUIRED | Existing manifest_hash; needs envelope binding |
| entra_governance | FOLLOW_UP_REQUIRED | FOLLOW_UP_REQUIRED | AUTHORITATIVE_CONFIGURATION_EXPORT | FOLLOW_UP_REQUIRED | No manifest signing |
| endpoint_inventory | FOLLOW_UP_REQUIRED | FOLLOW_UP_REQUIRED | AUTHORITATIVE_CONFIGURATION_EXPORT | FOLLOW_UP_REQUIRED | No manifest signing |
| oauth_inventory | FOLLOW_UP_REQUIRED | FOLLOW_UP_REQUIRED | AUTHORITATIVE_CONFIGURATION_EXPORT | FOLLOW_UP_REQUIRED | No manifest signing |
| oauth_risk | FOLLOW_UP_REQUIRED | FOLLOW_UP_REQUIRED | INFERENCE | FOLLOW_UP_REQUIRED | Classification-based |
| ai_tool_discovery | FOLLOW_UP_REQUIRED | FOLLOW_UP_REQUIRED | AUTHORITATIVE_CONFIGURATION_EXPORT | FOLLOW_UP_REQUIRED | Per-tool evidence_refs |
| ai_data_access_mapping | FOLLOW_UP_REQUIRED | FOLLOW_UP_REQUIRED | INFERENCE | FOLLOW_UP_REQUIRED | Derived from other scans |
| external_ai_risk_register | FOLLOW_UP_REQUIRED | FOLLOW_UP_REQUIRED | INFERENCE | FOLLOW_UP_REQUIRED | 3-layer cross-reference |
| ai_vendor_governance | FOLLOW_UP_REQUIRED | FOLLOW_UP_REQUIRED | AUTHORITATIVE_CONFIGURATION_EXPORT | FOLLOW_UP_REQUIRED | 4-layer evidence chain |
| sharepoint_onedrive | FOLLOW_UP_REQUIRED | FOLLOW_UP_REQUIRED | AUTHORITATIVE_CONFIGURATION_EXPORT | FOLLOW_UP_REQUIRED | No manifest signing |

**FOLLOW_UP_REQUIRED** means the scanner's runner does not yet call `EvidenceIntegrityService.build_envelope()`. The envelope service is available but integration is deferred to L14-SCAN-COMPLETENESS-001.

---

## 9. Chain-of-Custody Lifecycle

Custody events are recorded in `fa_evidence_custody_events` (append-only via DB trigger and ORM listener).

**Lifecycle flow for a typical scanner execution:**

```
COLLECTED    — scanner runner produces raw payload
INGESTED     — EvidenceIntegrityService stores envelope
VERIFIED     — digest check completes (VERIFIED_INTEGRITY_ONLY or INVALID)
NORMALIZED   — findings extracted to fa_normalized_findings
LOCKED       — QA approval locks evidence (H15 lifecycle)
REVIEWED     — assessor reviews evidence record
REFERENCED_IN_REPORT — report generation cites this evidence
```

Additional events: `EXPORTED`, `RETAINED`, `LEGAL_HOLD`, `SUPERSEDED`.

**Append-only enforcement:**
- DB trigger `fa_evidence_custody_append_only_trigger` raises `EXCEPTION` on UPDATE or DELETE
- ORM listeners (`@sa_event.listens_for`) raise `RuntimeError` on SQLAlchemy-level updates/deletes
- Application layer (`EvidenceCustodyService`) only calls INSERT

---

## 10. Tenant Isolation Rules

All evidence services enforce strict tenant isolation:

| Operation | Isolation mechanism |
|-----------|-------------------|
| `verify_by_id` | Returns `MISSING` on cross-tenant (not 403 — prevents existence leakage) |
| `batch_verify` | Per-ID check; cross-tenant IDs return `MISSING` individually |
| `custody_svc.record()` | Verifies tenant ownership; raises `PermissionError` on mismatch |
| `custody_svc.get_history()` | Verifies tenant ownership; raises `PermissionError` on mismatch |

**Golden rule:** Cross-tenant access MUST NEVER return any data about another tenant's evidence records. MISSING or PermissionError are the only acceptable outcomes.

The asymmetry (verify returns MISSING silently, custody raises) is intentional:
- Integrity verification is a read operation; silent MISSING prevents oracle attacks
- Custody modification is a write operation; explicit PermissionError requires explicit handling

---

## 11. Legacy Migration Behavior

Records in `fa_scan_results` created before migration 0201 have no corresponding `fa_scan_evidence_envelopes` row. The absence of an envelope must be treated as `provenance_status=UNVERIFIED` (not `VERIFIED_INTEGRITY_ONLY`, not `CONFIRMED`).

Historical `fa_normalized_findings` rows have `confidence_level=NULL` after migration 0201. Report generation logic must treat `NULL` confidence_level as `UNKNOWN` (fail-closed).

No backfill job is planned. Legacy records remain `UNVERIFIED` / `NULL` indefinitely unless a future re-scan creates new envelopes.

---

## 12. Report Integration Requirements

Scanner evidence envelopes must be linked to report generation in a future PR (L14-SCAN-REPORT-PROOF-001):

1. Report compiler must query `fa_scan_evidence_envelopes` for all scans referenced in the report
2. Any envelope with `provenance_status=INVALID` must block finalization or add a disclaimer
3. Confidence levels from `fa_normalized_findings.confidence_level` must appear in finding sections
4. `evidence_envelope_id` FK must be set on each `FaNormalizedFinding` created from a scan

---

## 13. Known Limitations

1. **Vault Transit not wired for scanner receipts.** `provenance_status` is `VERIFIED_INTEGRITY_ONLY`, not `VERIFIED_AUTHENTIC`. Future PR: L14-SCAN-VAULT-001.

2. **Scanner runner integration incomplete.** Only the envelope service is implemented; existing runners do not call `build_envelope()`. Follow-up: L14-SCAN-COMPLETENESS-001.

3. **`verify_by_id` cannot re-verify digest without the original payload.** The raw payload is stored in `fa_scan_results.payload`; a future enhancement should pass the payload through for full re-verification.

4. **Confidence fields on `fa_normalized_findings` are nullable.** Existing rows have `confidence_level=NULL`. Full enforcement requires a backfill strategy (deferred).

5. **AUTH-GAP-001 and AUTH-GAP-002 remain open.** See Section 14.

---

## 14. Known Gaps — AUTH-GAP-001 and AUTH-GAP-002

### AUTH-GAP-001: Customer Authorization Provenance Gap

**Status:** CLOSED at server-attested proof level for network/DNS/web scanners by L14-SCAN-AUTH-HARDENING-001 (see `L14_SCAN_AUTHORIZATION_HARDENING.md`). Customer-held signature and Graph-family binding remain open.

The current authorization model (`fa_scan_authorizations`, migration 0200) is operator-to-operator. Operators create scope records and activate them. There is no independently authenticated client consent receipt.

**What is missing:**
- A signed client consent receipt binding: scope, tenant, engagement, scanner types, timestamp
- The receipt must be verifiable offline by the client using only FrostGate's public key
- Until this exists, `authorization_ref` on envelopes is a reference to an operator-created record, not a client-signed receipt

**Fail-closed requirement:** Scanner dispatch without a valid client consent receipt MUST record `provenance_status=UNVERIFIED` (not `CONFIRMED`). Currently enforced at the service layer; the receipt itself is not implemented.

### AUTH-GAP-002: Background Execution Revalidation Gap

**Status:** CLOSED for network/DNS/web scanners by L14-SCAN-AUTH-HARDENING-001 (worker-start + per-boundary revalidation). Graph-family connectors: emergency-stop/cancel gate only.

**What is missing:**
- Re-validation of authorization at worker execution start
- A scan job is dispatched and queued; if the authorization expires or is revoked between dispatch and execution, the worker proceeds without re-checking

**Risk:** Stale authorization. Client revokes consent after a job is queued but before it runs.

**FVA-01 status:** `PARTIALLY_IMPLEMENTED` until execution-time revalidation is proven. The scope boundary is enforced at dispatch time only.
