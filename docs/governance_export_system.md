# FrostGate Governance Export System

## Doctrine

Governance exports are regulator-grade artifacts, not presentation output. The
canonical authority is the export manifest. PDF and HTML renderings are
deterministic delivery formats derived from that manifest.

## Manifest Semantics

The manifest records report identity, tenant ownership, lineage, reviewer state,
finding identifiers, evidence identifiers, framework mappings, remediation
records, confidence metadata, scoring metadata, and generation metadata.

Serialization is canonical JSON with sorted keys and compact separators. Unknown
or unserializable values fail export generation.

## Hashing Guarantees

The report hash is SHA-256 over canonical manifest serialization. Rendered PDF
or HTML bytes are never used as the authoritative hash input. Identical report,
evidence, mapping, remediation, scoring, lineage, and reviewer state produces an
identical manifest hash.

## Replay Guarantees

Replay verification rebuilds the canonical manifest from persisted report state
and compares the rebuilt SHA-256 hash to the stored or caller-supplied hash.
Mismatch, missing required sections, incomplete lineage, or invalid evidence
links fail closed and emit verification audit events.

## Immutability Rules

Finalized exports preserve reviewer reference, approval timestamp, immutable
finalized version, and finalized manifest hash. Post-finalization regeneration
creates a new report version with prior/following lineage instead of mutating
the finalized artifact.

## Reviewer Finalization

Reviewer finalization requires an explicit reviewer reference. The finalized
manifest includes reviewer status and approval timestamp. Reviewer approval is
never fabricated by export generation.

## Evidence Appendix

The evidence appendix is deterministic and ordered by evidence ID. Entries carry
evidence lineage, provenance, validation state, freshness, source metadata,
linked findings, and linked controls. Findings must link only to known evidence,
and evidence must link only to known findings.

## Audit Trail

Export generation, download, finalization, replay request, replay completion,
hash verification, hash verification failure, replay mismatch, regeneration,
reviewer assignment, and supersession produce audit events with stable report
and assessment identifiers. Audit metadata excludes report content, prompts,
model output, and evidence payload bodies.

## Tenant Isolation

Export retrieval uses tenant-scoped predicates derived from authenticated request
context. ID-only retrieval is forbidden. Pre-tenant lead reports require the
assessment ownership header already used by report retrieval.

## AI Narrative Containment

AI-generated narrative is isolated under `ai_narrative` and marked advisory-only.
It does not control finding IDs, evidence links, framework mappings, confidence
scores, remediation records, manifest serialization, or report hashes.
