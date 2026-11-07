# L14 Scan Audit Corrections

**Document ID:** L14-SCAN-AUDIT-CORRECTIONS-001  
**Date:** 2026-11-06  
**Branch:** test/l14-scan-accuracy-001  
**Corrects:** L14-FIELD-SCAN-DEEP-AUDIT.md, L14-FIELD-SCAN-INVENTORY.md, L14_SCAN_AUDIT_MANIFEST.json  
**Status:** ACTIVE — supersedes claims in original audit documents where noted

---

## Purpose

This document corrects specific inaccurate or imprecise claims made in the original L14-FIELD-SCAN-DEEP-AUDIT-001 audit documents. Each correction is identified by section and issue type. The original documents are retained unchanged as the historical record.

---

## Correction 1 — Scanner Accounting: Architecture Layer Distinctions

### Original claim (L14_FIELD_SCAN_INVENTORY.md, L14_SCAN_AUDIT_MANIFEST.json)

The audit states "14 connectors have runner implementations" and tallies them uniformly. The machine-readable manifest records `connectors_with_full_runner_implementations: 10`.

### Corrected classification

FrostGate's scanner connectors should be categorized across four distinct layers, not counted as a flat list:

**Layer A — Independently Executable Field Scanners** (can be invoked standalone against a target):
- `network_scan` — IMPLEMENTED_AND_TESTED
- `web_headers` — IMPLEMENTED_AND_TESTED
- `dns_email` — IMPLEMENTED_AND_TESTED
- `microsoft_graph` (full orchestrator) — IMPLEMENTED_AND_TESTED
- `entra_governance` — IMPLEMENTED_AND_TESTED
- `endpoint_inventory` — IMPLEMENTED_AND_TESTED
- `oauth_inventory` — IMPLEMENTED_AND_TESTED
- `oauth_risk` — IMPLEMENTED_AND_TESTED
- `sharepoint_onedrive` — IMPLEMENTED_AND_TESTED

Layer A count: **9 independently executable scanners**

**Layer B — Integrated AI Chain Stages** (require prior stage output; together form 1 pipeline):
- `ai_tool_discovery` — Stage 1 of 4 (requires Graph token + vendor registry)
- `ai_data_access_mapping` — Stage 2 of 4 (derives from ai_tool_discovery output)
- `external_ai_risk_register` — Stage 3 of 4 (scores vendors based on Stage 1/2)
- `ai_vendor_governance` — Stage 4 of 4 (generates governance findings from Stages 1-3)

Layer B counts as: **1 integrated AI governance pipeline with 4 stages**. Each stage is independently callable but designed to consume prior stage outputs. Counting all 4 as independent scanners inflates the scanner count and obscures the pipeline dependency.

**Layer C — Registered-Only Stubs** (enum entries only; no runner implementations):
- `google_workspace`, `aws`, `azure`, `gcp`

Layer C count: **4 registered stubs, NOT scanners**

**Layer D — Connector Bridges** (field assessment service wiring, not runners):
- These exist in `services/field_assessment/connectors/` and bridge FA state to runners.

**Corrected total**: 9 Layer-A independent scanners + 1 Layer-B AI pipeline (4 stages) = **10 callable execution units**, of which **4 are registered-only with no implementation**.

---

## Correction 2 — Test Count Accounting: No Additive Overlapping Suites

### Original claim (L14_SCAN_AUDIT_MANIFEST.json)

The manifest lists test suites with counts including overlapping invocations (e.g., test_scan_import.py appears in multiple suite entries). The total `tests_executed: 476` may double-count overlapping tests.

### Corrected methodology

Test counts must be deduplicated. If `pytest -k "scan"` and `pytest -k "connector"` run on the same suite, the intersection is counted only once. The manifest's `test_suites_run` entries share files across multiple bullets. The correct approach is a single pytest invocation of the full relevant suite with `--collect-only` to get a deduplicated count.

**Corrected guidance**: Report a single pytest invocation with exact command and deduplicated count. Do not add counts from overlapping -k filter runs.

---

## Correction 3 — Detection Maturity Labels

### Original claim

The scorecard uses a single "Maturity" column with labels like IMPLEMENTED_AND_TESTED. The accuracy column scores (1–5) acknowledge uncertainty but do not label detection effectiveness separately from implementation maturity.

### Corrected labeling schema

Each scanner must carry two independent labels:

**Implementation Maturity** (what is built):
- `IMPLEMENTED_AND_TESTED` — Runner exists, tests cover the runner contract
- `IMPLEMENTED_NOT_VERIFIED` — Runner exists, no contract tests
- `PARTIALLY_IMPLEMENTED` — Runner exists but incomplete (missing branches or finding types)
- `REGISTERED_NO_RUNNER` — Only enum/schema registered; no executable runner
- `MISSING` — Not registered, not implemented
- `DEPRECATED` — Exists but marked for removal

**Detection Effectiveness** (how accurately it finds real conditions):
- `NOT_MEASURED` — No known-answer ground-truth evaluation performed (applies to ALL scanners prior to L14-SCAN-ACCURACY-001)

As of this document, all scanners are `NOT_MEASURED` for live detection effectiveness. L14-SCAN-ACCURACY-001 introduces `FIXTURE_VALIDATED` status for fixture-level accuracy.

---

## Correction 4 — Security Claim Precision: "SSRF-proof" and "Completely Secure"

### Original claim (L14_FIELD_SCAN_DEEP_AUDIT.md)

The executive summary states "Zero P0 findings. No SSRF vulnerability... were found." A later section states "SSRF status: SECURE."

### Correction

**What was tested**: The 114 `test_c6_scanner_containment.py` tests cover `SafeTargetValidationService` unit-level behavior — RFC1918/RFC4193/loopback/link-local/CGNAT/multicast/cloud-metadata/DNS-rebinding/IPv4-mapped-IPv6/CIDR validation/rate-limiting. These are **unit tests of a Python library class**, not end-to-end field validation of a deployed scanning system.

**What was NOT tested**:
- DNS-over-HTTPS resolvers that may bypass the validator's DNS resolution
- IPv6 scope IDs, zone IDs, or non-normalized IPv6 forms not covered in test corpus
- TOCTOU between validation and connection (kernel-level race conditions in long-running scans)
- Interactions with custom Python DNS resolvers or monkey-patching
- TLS SNI-based routing that bypasses IP-level validation

**Corrected language**: "SafeTargetValidationService has 114 unit-level containment tests that passed. No SSRF bypass was found in source inspection. End-to-end deployed field validation has not been performed." Remove "SSRF-proof" and "completely secure" from all documents.

---

## Correction 5 — Cryptographic Assertion: SHA-256 Digest ≠ Digital Signature

### Original claim (L14_SCAN_EVIDENCE_INTEGRITY.md, L14_FIELD_SCAN_DEEP_AUDIT.md)

References to "evidence hashing" and "signed manifests" may imply cryptographic signing parity across all scanners.

### Correction

**Microsoft Graph connector** (`services/connectors/msgraph/integrity.py`): Uses HMAC-SHA256 signing of the manifest. This is a Message Authentication Code — it provides integrity and authenticity relative to a shared secret. It is NOT a digital signature (asymmetric cryptography).

**Network scan and web headers runners**: Produce SHA-256 digests (`scan_id = uuid.uuid4().hex`). A UUID is NOT a hash of the payload content. It is an identity token, not an integrity proof. No content hash is produced at the runner level.

**Corrected terminology**:
- SHA-256 hash of a payload = **integrity check** (detects modification, proves content)
- HMAC-SHA256 = **message authentication code** (proves origin relative to shared secret)
- RSA/ECDSA signature = **digital signature** (asymmetric; proves origin without shared secret)
- UUID = **identifier** (not integrity proof)

The network_scan and web_headers runners DO NOT produce cryptographic integrity proofs at the runner level. This is a documented gap. The FA evidence chain (FaEvidenceLink + FaScanResult) may add integrity at the ingestion layer, but that is distinct from runner-level signing.

---

## Correction 6 — Compliance Claim Precision: NIST AI RMF Mapping ≠ Certification

### Original claim (L14_FIELD_SCAN_DEEP_AUDIT.md, L14_SCAN_FRAMEWORK_COVERAGE.md)

"NIST AI RMF: Strongly covered by the AI governance chain." Finding types are mapped to NIST AI RMF control IDs.

### Correction

**What exists**: Finding type → NIST AI RMF control ID mappings in `_FINDING_NIST_MAP`. These are manually authored control-to-finding associations.

**What this is NOT**:
- Not an accredited NIST AI RMF assessment
- Not a government certification
- Not a third-party audit opinion
- Not a gap analysis against the full NIST AI RMF control catalog
- Not a determination that FrostGate itself complies with NIST AI RMF

**Corrected claim**: "FrostGate includes finding type to NIST AI RMF control mappings to assist customers in understanding which findings are relevant to NIST AI RMF compliance programs. Passing assessments that produce these findings does NOT constitute NIST AI RMF certification or audit readiness."

---

## Correction 7 — DNS/Email SafeTargetValidationService Asymmetry

### Original claim (P1-002 in L14_SCAN_AUDIT_MANIFEST.json)

"The dns_email runner performs DNS queries for domains passed directly without routing through SafeTargetValidationService."

### Corrected classification: ARCHITECTURAL_ASYMMETRY_DOCUMENTED

This is **not a vulnerability**. The clarification is as follows:

`SafeTargetValidationService` validates socket-opening targets (IP/hostname/URL) to prevent SSRF attacks where outbound socket connections could reach internal infrastructure. DNS lookups are passive read operations that cannot open a socket to an internal service endpoint.

**Why dns_email doesn't use SafeTargetValidationService**:
- DNS queries cannot reach RFC1918 internal services via the DNS protocol
- A DNS query for `evil.example.com` cannot cause the scanner to connect to `192.168.1.1`
- The validator was designed for pre-socket validation, not DNS query validation

**What risk remains**:
- DNS amplification: not applicable (scanner is a client, not a reflector)
- DNS rebinding: only relevant if the scanner subsequently connects to the resolved IP (dns_email does not)
- DNS data exfiltration via subdomain queries: possible but out of threat model for a governance scanner

**Corrected label**: ARCHITECTURAL_ASYMMETRY_DOCUMENTED (not a vulnerability, not a gap in coverage, but a deliberate design difference that should be documented in the safety architecture).

---

## Correction 8 — Confidence Ambiguity in Finding Output

### New finding (not in original audit)

The original audit did not assess whether scanner findings carry explicit confidence levels. As of L14-SCAN-ACCURACY-001, the following gap is now documented:

**All scanner runners** (network_scan, web_headers, dns_email, endpoint_inventory, oauth_inventory, oauth_risk, ai_tool_discovery) produce findings without an explicit `confidence` field. All findings are implicitly PROBABLE or SUSPECTED based on the evidence type.

**Gap**: No finding currently carries a machine-readable `confidence` classification. The normalized finding path (`FaNormalizedFinding`) does not enforce confidence classification. This is deferred to L14-ASSESSMENT-ASSURANCE-001 for full enforcement.

---

## Summary of Corrections

| ID | Issue | Original Document | Status |
|----|-------|-------------------|--------|
| COR-001 | Scanner counting: 14 "connectors" vs 9 independent + 1 pipeline + 4 stubs | L14_FIELD_SCAN_INVENTORY.md | CORRECTED |
| COR-002 | Test count additive overlap | L14_SCAN_AUDIT_MANIFEST.json | CORRECTED |
| COR-003 | Missing detection effectiveness label (NOT_MEASURED) | L14_FIELD_SCAN_DEEP_AUDIT.md | CORRECTED |
| COR-004 | "SSRF-proof" / "completely secure" overclaim | L14_FIELD_SCAN_DEEP_AUDIT.md | CORRECTED |
| COR-005 | SHA-256 UUID != cryptographic integrity proof | L14_SCAN_EVIDENCE_INTEGRITY.md | CORRECTED |
| COR-006 | NIST AI RMF mapping != NIST certification | L14_FIELD_SCAN_DEEP_AUDIT.md | CORRECTED |
| COR-007 | dns_email SafeTargetValidationService gap misclassified | L14_SCAN_AUDIT_MANIFEST.json | RECLASSIFIED |
| COR-008 | No confidence field in finding output | (New gap) | DOCUMENTED |
