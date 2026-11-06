# FrostGate Finding Confidence Policy

**Document ID:** FROSTGATE-FINDING-CONFIDENCE-POLICY-001  
**Version:** 1.0  
**Date:** 2026-11-06  
**Authority:** FrostGate Internal Engineering Standard  
**Applies to:** All FrostGate field assessment findings produced by any scanner connector  
**Status:** POLICY_ONLY — enforcement partially deferred to L14-ASSESSMENT-ASSURANCE-001

---

## Purpose

This policy defines the evidence confidence model for all FrostGate assessment findings. It establishes:
1. Exactly what confidence levels are permitted
2. What verification methods are recognized
3. What rules govern the assignment of confidence
4. That confidence and severity are independent dimensions

This policy governs both human-reviewed findings and scanner-generated findings.

---

## 1. Evidence Confidence Levels

Five confidence levels are defined. They are mutually exclusive — each finding must have exactly one.

### CONFIRMED

**Definition**: Direct technical observation from an authoritative source; meets all required criteria. The condition was directly observed or extracted from an authoritative configuration source.

**Minimum evidence requirement**:
- At least one of: DIRECT_TECHNICAL_OBSERVATION or AUTHORITATIVE_CONFIGURATION_EXPORT

**Prohibited**:
- CONFIRMED with only INTERVIEW_ASSERTION is not permitted
- CONFIRMED with only INFERENCE is not permitted
- CONFIRMED when primary evidence source is unavailable (access denied, timeout, collection error)

**Examples**:
- Port 3389 observed open in network scan: CONFIRMED observation
- SPF record retrieved from DNS: CONFIRMED record state
- 403 on Intune API: CANNOT be CONFIRMED about device encryption state

### PROBABLE

**Definition**: Strong supporting evidence with minor gaps. Primary evidence exists. Independent corroboration not yet complete.

**Minimum evidence requirement**:
- At least one of: DIRECT_TECHNICAL_OBSERVATION, AUTHORITATIVE_CONFIGURATION_EXPORT, DOCUMENT_REVIEW

**Use when**:
- Primary evidence is present but independent corroboration is absent
- Assessment is based on a single authoritative source without cross-validation

**Examples**:
- MFA registration data from Graph API (single source, no enforcement verification): PROBABLE
- DMARC record present and parsed (passive DNS, no MX flow test): PROBABLE

### SUSPECTED

**Definition**: Partial or indirect evidence. More investigation needed before concluding.

**Minimum evidence requirement**:
- None required; partial or indirect evidence justifies this level

**Use when**:
- Evidence is indirect, inferred, or circumstantial
- Multiple evidence sources would be needed to elevate to PROBABLE or CONFIRMED
- Collection partially failed

**Examples**:
- AI vendor detected via name match without OAuth data: SUSPECTED
- DPA unknown status (may or may not exist): SUSPECTED

### UNKNOWN

**Definition**: Insufficient evidence to classify. Data collection was not possible or was insufficient.

**Use when**:
- Collection failed (timeout, access denied, resolver error)
- Prerequisite data was unavailable
- The evidence scope was not covered in this assessment

**Critical rule**: Missing data must produce UNKNOWN, not CONFIRMED_ABSENT. Inability to collect evidence does NOT confirm absence of a control.

**Examples**:
- DNS timeout: cannot determine SPF status -> UNKNOWN (not SPF_MISSING confirmed)
- Intune 403: cannot determine encryption status -> UNKNOWN (not UNENCRYPTED confirmed)

### NOT_ASSESSED

**Definition**: Finding type or domain was out of scope for this assessment. The condition was not evaluated.

**Use when**:
- Scan source type was not configured for this engagement (e.g., AWS not in scope)
- Technical capability was not available (e.g., P2 license required)

**Examples**:
- Identity Protection risky users (requires P2 license): NOT_ASSESSED
- Cloud infra scan when only M365 scope authorized: NOT_ASSESSED

---

## 2. Verification Methods

Seven verification methods are defined. Multiple methods may apply to a single finding.

### DIRECT_TECHNICAL_OBSERVATION

**Definition**: The scanner directly observed the condition. A tool made a live request, received a response, and the finding is derived from that response.

**Examples**:
- Port 443 connection succeeded; TLS certificate retrieved
- HTTP HEAD response included `Strict-Transport-Security` header
- Graph API returned device compliance state

**Required for CONFIRMED**: This or AUTHORITATIVE_CONFIGURATION_EXPORT must be present.

### AUTHORITATIVE_CONFIGURATION_EXPORT

**Definition**: Configuration exported from an authoritative source (e.g., Azure AD tenant export, Intune policy export, DNS zone file). The data represents the actual configured state.

**Examples**:
- Azure AD Conditional Access policy export
- DNS zone records from authoritative nameserver
- Microsoft Graph security reports

**Required for CONFIRMED**: This or DIRECT_TECHNICAL_OBSERVATION must be present.

### INDEPENDENT_CORROBORATION

**Definition**: A second independent evidence source confirms the same finding. The two sources must be methodologically independent (not derived from the same underlying data).

**Examples**:
- Port observed open in network scan AND confirmed by reviewing firewall rules
- MFA enforced per CA policy AND confirmed by auditing sign-in logs

**Note**: Two calls to the same API are NOT independent corroboration.

### DOCUMENT_REVIEW

**Definition**: Supporting documentation was reviewed (policy documents, vendor SOC 2 reports, contracts, technical architecture diagrams).

**Strength**: Lower than technical observation. Documents may be outdated or not reflecting actual deployed state.

### INTERVIEW_ASSERTION

**Definition**: A stakeholder stated the condition is or is not in place. Weakest verification method.

**Limitations**:
- Cannot alone support CONFIRMED confidence
- Subject to recall error, misunderstanding, and misrepresentation
- Must be corroborated by at least one technical method before elevating confidence

### INFERENCE

**Definition**: The finding is logically derived from other confirmed evidence. The condition is not directly observed but is reasonably concluded.

**Examples**:
- If no MX record present, email cannot be received (inferred from MX_MISSING)
- If DMARC policy is p=none, spoofed mail will not be rejected (inferred from policy state)

**Limitations**: Cannot alone support CONFIRMED confidence.

### NOT_VERIFIED

**Definition**: No verification method was applied. The finding is generated algorithmically from the scan data but has not been independently verified.

**Use when**:
- Scanner-generated finding with no secondary verification
- Finding is pending assessor review

---

## 3. Confidence Assignment Rules

### Rule 3.1 — CONFIRMED requires authoritative evidence

A finding may only be classified CONFIRMED if at least one of the following verification methods is present:
- DIRECT_TECHNICAL_OBSERVATION
- AUTHORITATIVE_CONFIGURATION_EXPORT

### Rule 3.2 — CONFIRMED with only INTERVIEW_ASSERTION is prohibited

CONFIRMED + INTERVIEW_ASSERTION (only) is a policy violation. If INTERVIEW_ASSERTION is the only method, confidence must be PROBABLE or lower.

### Rule 3.3 — CONFIRMED with only INFERENCE is prohibited

Logical deduction without direct observation cannot support CONFIRMED confidence.

### Rule 3.4 — PROBABLE minimum for primary evidence without corroboration

When primary technical evidence exists but independent corroboration is absent, PROBABLE is the minimum confidence level.

### Rule 3.5 — Confidence and severity are independent

Confidence describes the quality of evidence. Severity describes the impact if the finding is accurate.

Permitted combinations:
- SUSPECTED + HIGH: Partial evidence for a high-impact condition — HIGH severity because if confirmed, the impact is high
- CONFIRMED + LOW: Direct observation of a low-impact condition
- UNKNOWN + CRITICAL: If a condition's impact is critical but evidence is missing, severity can still be CRITICAL with UNKNOWN confidence to flag for investigation

There is no rule that high confidence implies high severity or vice versa.

### Rule 3.6 — Missing data must produce UNKNOWN or NOT_ASSESSED

A collection failure (timeout, access denied, resolver error, permission denied) must result in UNKNOWN or NOT_ASSESSED confidence for findings dependent on that data.

**Prohibited**: Classifying a finding as CONFIRMED_ABSENT based solely on a collection error or empty return set.

**Example violations**:
- DNS timeout -> claiming SPF_MISSING (CONFIRMED) = policy violation
- Intune 403 -> claiming zero encrypted devices (CONFIRMED) = policy violation
- Empty Graph response with valid perms -> claiming zero risky users (CONFIRMED) = ambiguous (may be valid)

**Example of valid behavior**:
- DNS timeout -> collection_status=TIMEOUT, no SPF finding emitted
- Intune 403 -> collection_status=DENIED, no unencrypted_devices finding emitted

---

## 4. Implementation Status

| Component | Status | Gap |
|-----------|--------|-----|
| Confidence model defined (this document) | IMPLEMENTED | — |
| Confidence model tested (`test_confidence_model.py`) | IMPLEMENTED | — |
| `confidence` field in runner finding output | NOT_IMPLEMENTED | All runners |
| `confidence` field in `FaNormalizedFinding` schema | NOT_IMPLEMENTED | Deferred to L14-ASSESSMENT-ASSURANCE-001 |
| Confidence enforcement at report generation | NOT_IMPLEMENTED | Deferred to L14-SCAN-REPORT-PROOF-001 |
| Automatic confidence downgrade on collection error | NOT_IMPLEMENTED | Deferred to L14-ASSESSMENT-ASSURANCE-001 |

---

## 5. Cross-References

- `tests/test_scan_accuracy/test_confidence_model.py` — Tests enforcing Rules 3.1–3.6
- `docs/assurance/FROSTGATE_VERIFIED_ASSESSMENT_STANDARD.md` — FVA-02 (Evidence Sufficiency), FVA-03 (Finding Accuracy)
- `docs/audits/L14_SCAN_AUDIT_CORRECTIONS.md` — COR-003 (detection maturity), COR-008 (confidence field gap)
- L14-ASSESSMENT-ASSURANCE-001 — Full enforcement gate PR (future)
