# Deterministic Governance Reporting — Doctrine and Guarantees

## Purpose

FrostGate governance reports are deterministic, replayable, evidence-backed artifacts.
This document defines the doctrine, semantics, and invariants that govern how reports
are generated, verified, and exported.

---

## Deterministic Reporting Doctrine

A governance report is **deterministic** when identical inputs always produce an
identical output.  Determinism enables:

- **Replay verification** — regulators can re-derive the same report from the same evidence.
- **Tamper detection** — any mutation of report content breaks the manifest hash.
- **Idempotent submission** — submitting the same inputs twice produces the same report_id.
- **Audit trail integrity** — finding IDs are stable across assessments and time periods.

All determinism properties are enforced at the service layer (`services/governance/report/`).
No AI model output may appear in any frozen field of a `GovernanceReport`.

---

## Finding ID Generation Semantics

Finding IDs are derived via SHA-256 of a canonical JSON payload:

```
finding_id = SHA-256({
    "tenant_id": <str>,
    "framework": <str>,
    "control_id": <str>,
    "gap_classification": <str>,
    "evidence_state_hash": <str>
})[:16]  -- first 16 hex chars
```

**Stability guarantee:**
Two governance assessments of the same tenant, framework, control, gap classification,
and evidence state hash ALWAYS produce the same finding_id — regardless of when or
how many times the assessment is run.

This means:
- Finding IDs are stable cross-report references.
- Changes to evidence state (e.g. new validation) produce a new finding_id.
- Finding IDs can be used as deduplication keys in downstream SIEM/GRC integrations.

---

## Confidence Methodology

Confidence is scored deterministically from four components:

| Component             | Weight | Formula                                              |
|-----------------------|--------|------------------------------------------------------|
| evidence_completeness | 0.40   | `validated_count / total_count`                      |
| evidence_freshness    | 0.30   | `mean(1 - min(days/90, 1))` for refs with freshness  |
| control_coverage      | 0.20   | `validated_count / max(total_count, 1)`              |
| reviewer_validated    | 0.10   | `1.0` if validated, else `0.0`                       |

**Overall score:**

```
overall = (
    0.4 * evidence_completeness
    + 0.3 * evidence_freshness
    + 0.2 * control_coverage
    + 0.1 * reviewer_weight
) * (assessment_completion_pct / 100)
```

**Degradation reasons** are populated whenever any component falls below 0.5.
The score fails closed: empty evidence → overall = 0.0.

---

## Evidence Linkage

Evidence references (`EvidenceRef`) are deterministic identifiers for compliance evidence:

- `evidence_id`: derived from `(source, classification, provenance_key)` via SHA-256.
- `validation_state`: `VALIDATED | PENDING | MISSING` — never collapses to optimistic.
- `freshness_days`: explicit staleness tracking; `None` = unknown (treated as stale).

Evidence is linked to findings via `evidence_ids` in `GovernanceFinding`.
The evidence appendix in `GovernanceReport` carries the full `EvidenceRef` list for audit.

**Evidence state hash**: the hash of all evidence IDs for a domain, used in finding_id
derivation.  Changes to evidence (new refs, validation state changes) propagate to
new finding IDs, preserving lineage integrity.

**Evidence domain matching fallback:** If `evidence_refs` are provided but none match the
finding's domain, the engine logs a warning (`governance_report.evidence_domain_unmatched`)
and proceeds with an empty `evidence_ids` for that finding.  The finding is still generated —
confidence degrades to reflect absent evidence.  This is intentional fail-open behavior: missing
evidence linkage surfaces as low confidence rather than a hard error, so partial-evidence
assessments still produce actionable reports.

---

## Framework Mapping Semantics

All framework mappings are **hardcoded authoritative lookups** in
`services/governance/report/framework_mappings.py`.

No LLM inference is used.  Mappings cover:

- **NIST AI RMF**: GOVERN, MAP, MEASURE, MANAGE categories.
- **SOC 2**: CC1–CC9, A1, C1, PI1, P1–P8 Trust Services Criteria.
- **HIPAA**: Administrative, Physical, Technical safeguard categories.

Mapping lookup priority:
1. `control_id` exact match (confidence = 0.95)
2. `domain` exact match (confidence = 0.90)
3. Unknown control/domain → empty list

Mappings are deterministic: same `(control_id, domain)` always returns the same
`FrameworkMapping` list in the same order.

---

## Replay Guarantees

`GovernanceReportEngine.replay()` re-generates a report from the same inputs and
returns `(new_report, hash_matches: bool)`.

**hash_matches = True** proves:
- The stored report was not tampered with after generation.
- Evidence has not been swapped or modified.
- Confidence scoring has not been manipulated.

**Note:** `generated_at` (ISO timestamp) is intentionally excluded from the manifest
hash — timestamps vary across runs.  All other deterministic fields are covered.

**Replay contract:**
- `canonical_inputs_hash` covers: `assessment_id`, sorted `evidence_ids`, sorted `framework_ids`.
- `findings_hash` covers: sorted `finding_ids` of all findings.
- `manifest_hash` covers: all frozen fields except `manifest_hash` itself and `generated_at`.

---

## Manifest Hash Guarantees

The manifest hash is a SHA-256 digest of the canonical JSON of all deterministic
report fields, excluding `manifest_hash` and `generated_at`.

```
manifest_hash = SHA-256(canonical_json({
    assessment_id, confidence, evidence_appendix, findings,
    framework_summary, remediations, report_id, schema_version,
    tenant_id, version
}))
```

- `sort_keys=True, separators=(",", ":")` — no whitespace variance.
- JSON encoding is UTF-8, `ensure_ascii=True`.
- Schema version pin: `schema_version = "1.0"`.  Increment when field semantics change.
- `is_finalized=True` DB records are immutable — the manager layer enforces this.

---

## AI Narrative Containment Rules

AI-generated narrative is **advisory-only** and isolated from all deterministic fields:

1. **No AI prose in `GovernanceFinding.description`** — description is templated
   from control_id, domain, score, and gap_classification only.
2. **No AI prose in any frozen field** — `GovernanceReport`, `GovernanceFinding`,
   `RemediationEntry`, `EvidenceRef`, `ConfidenceScore` all use `frozen=True`.
3. **Manifest hash covers no AI output** — if AI narrative is added as a separate
   field, it must be excluded from the manifest hash computation.
4. **Replay verification ignores AI fields** — `replay()` only checks deterministic
   fields via manifest hash comparison.
5. **HTML/PDF exports label AI sections** — any advisory section must be clearly
   labelled as "advisory-only, not part of the deterministic governance record".

Violation of these rules breaks the tamper-evidence guarantee.

---

## Schema Version Policy

`schema_version = "1.0"` is the initial wire format.

- Increment patch for additive field additions (backward-compatible).
- Increment minor for field semantic changes (new serialization logic required).
- Increment major for breaking changes (new deserialize path required).
- `deserialize_report()` rejects unknown schema versions with `ValueError`.

---

## Tenant Isolation

All governance reports are tenant-scoped:
- `tenant_id` is always resolved from auth context — never from request body.
- All DB queries include a `tenant_id` predicate (fail-closed on mismatch).
- RLS is enabled on `governance_reports` table.
- `finding_id` includes `tenant_id` in its derivation — cross-tenant finding ID collision is impossible.
