# Governance Digital Twin 18.8.1

## Mission

PR 18.8.1 establishes the deterministic Governance Digital Twin foundation for FrostGate.
It produces a replay-safe, fingerprinted, tenant-scoped snapshot of current governance state
without inventing links, generating synthetic authority data, or exposing unsafe payloads.

This PR is intentionally a service-first foundation.
API route exposure is deferred so the state model, fingerprinting, and redaction shell can
stabilize before contract and plane-surface expansion.

## Architecture

Bounded context: `services/governance_digital_twin/`

Modules:

- `models.py` — pure dataclasses and enums for snapshots, manifests, validation reports, provenance, identity, relationships, authority graph, and baselines
- `builder.py` — deterministic tenant-scoped snapshot construction over existing authoritative SQLAlchemy models
- `validator.py` — graph integrity, invariant, and replay-integrity validation
- `manifest.py` — deterministic audit-envelope generation
- `contract.py` — internal service contract preventing bypass of the twin engine
- `mcim.py` — MCIM registration adapter consuming the shared registration manifest
- `fingerprint.py` — SHA-256 canonical JSON hashing with explicit fingerprint-domain separation
- `exporter.py` — replay-safe export projection with redaction enforcement
- `baseline.py` — deterministic comparison-baseline generation
- `redaction.py` — forbidden-field stripping and fail-closed validation

The builder reads only existing backend sources. It does not create or persist new authority state.
Every exported ID is deterministic, every list is stable-sorted, every timestamp is normalized to UTC `Z` form, and snapshot payload mappings are deep-frozen before they are attached to the canonical snapshot.

## Entity Model

Canonical entity types supported by the snapshot:

- `policy`
- `control`
- `evidence`
- `finding`
- `remediation`
- `assessment`
- `report`
- `decision`
- `workflow`
- `simulation`
- `replay`
- `customer`
- `framework`
- `authority`

Every entity contains the required canonical fields plus enterprise replay metadata:

- `id`
- `type`
- `authority`
- `source_ref`
- `title`
- `status`
- `created_at`
- `updated_at`
- `confidence`
- `tenant_scope`
- `replay_safe`
- `redaction_state`
- `metadata_hash`

The twin stores only replay-safe identity and state attributes directly.
Potentially sensitive source metadata is represented as `metadata_hash`, not as raw payload.

## Relationship Model

Canonical relationship types supported by the snapshot:

- `governs`
- `verifies`
- `maps_to`
- `supports`
- `contradicts`
- `remediates`
- `generated_from`
- `published_to`
- `decided_by`
- `depends_on`
- `supersedes`
- `derived_from`
- `affects`
- `owned_by`

Every relationship contains:

- `id`
- `type`
- `from_entity_id`
- `to_entity_id`
- `authority`
- `confidence`
- `evidence_refs`
- `created_at`
- `replay_safe`
- `metadata_hash`

## Authority Graph

The authority graph snapshot models:

- available authorities that contributed to the twin state
- source tables and route prefixes when known
- ownership domain
- produced entity types
- consumed entity types
- downstream dependencies inferred from explicit cross-authority links

This graph is intentionally impact-analysis-ready.
Future simulation and closed-loop execution can inspect which authorities depend on evidence, controls,
framework mappings, decision records, and report outputs before applying a change.

## Snapshot Fingerprinting

Fingerprint method:

- SHA-256 over canonical JSON
- stable key ordering via `services.canonical.canonical_json_bytes`
- stable entity ordering
- stable relationship ordering
- normalized timestamps
- includes explicit domain string `FG_GOVERNANCE_DIGITAL_TWIN_V1`
- includes `snapshot_version`
- includes entity hashes
- includes relationship hashes
- includes redaction profile
- excludes runtime-assigned fingerprint and export envelope

Generated time is deterministic.
It is derived from the latest normalized entity or relationship timestamp in the snapshot, not from wall-clock execution time.

## Replay-Safe Export

`export_replay_safe_snapshot()` emits:

- `snapshot_id`
- `fingerprint`
- `generated_at`
- `snapshot_version`
- `source_authorities`
- `redaction_profile`
- `entity_summaries`
- `relationship_summaries`
- `limitations`
- `warnings`
- `replay_instructions`

The export excludes secrets, prompts, vectors, provider payloads, cookies, sessions, and similar unsafe fields.

## Redaction Model

Forbidden keys blocked by the redaction shell:

- `secret`
- `token`
- `password`
- `api_key`
- `auth_header`
- `authorization`
- `raw_prompt`
- `raw_vector`
- `embedding`
- `provider_payload`
- `private_key`
- `session`
- `cookie`

Behavior:

- forbidden fields are dropped
- warnings are recorded
- raw values are never surfaced
- unsupported payload shapes raise a redaction error instead of silently passing through

## Comparison Baseline

`create_comparison_baseline()` creates a deterministic comparison-ready structure with:

- baseline identity
- snapshot identity and fingerprint
- entity counts by type
- relationship counts by type
- authority counts
- completeness summary
- replay-safe marker

This PR does not implement diffing or scenario replay storage.
It only creates the baseline object that later comparison flows can consume.

## API Route Deferral

API shell is intentionally deferred in PR 18.8.1.

Reason:

- the deterministic state model, replay-safe export, and verification contract are the non-negotiable foundation
- route registration would require contract regeneration, plane registry updates, route inventory sync, and OpenAPI churn
- delaying the public surface keeps this PR focused on correctness and replay safety

Planned follow-on surfaces after stabilization:

- `GET /governance-digital-twin/snapshot`
- `GET /governance-digital-twin/snapshot/export`
- `POST /governance-digital-twin/baselines`


## Constitution

Permanent rule: nothing computes governance state outside the Governance Digital Twin bounded context.
State is built first, validated second, fingerprinted third, and only then projected for presentation.

See [GOVERNANCE_DIGITAL_TWIN_CONSTITUTION.md](/home/jcosat/Projects/fg-core/docs/GOVERNANCE_DIGITAL_TWIN_CONSTITUTION.md) for the permanent law set.

## Limitations

Current intentional limits in 18.8.1:

- replay entities are deferred until a persisted replay authority exists
- baseline lookup storage is deferred; only requested baseline references are captured in snapshot builds
- portal participation is modeled as authority input, not as a standalone exported entity type
- policy, workflow, decision, and simulation links are extracted only when explicit IDs are present in existing records
- no guessed edges are created

## Future Use

### 18.8.2 Scenario Simulation & Impact Analysis

This foundation provides:

- deterministic current-state snapshot input
- authority dependency graph
- baseline creation surface
- canonical fingerprinting for scenario reproducibility

### 18.8.3 Closed-Loop Governance Execution

This foundation provides:

- authoritative state input for safety checks
- explicit policy/control/finding/remediation linkage
- replay-safe export for pre/post execution attestation
- tenant-scoped deterministic context for execution guards

## AGI Governance Readiness

The twin is AGI-ready in the narrow, enterprise-safe sense:

- authority attribution is explicit
- unsupported or unsafe payloads fail closed
- snapshot identity is deterministic
- exported state is replay-safe
- linked governance state is machine-verifiable instead of narrative-only

This makes future autonomous planning and remediation safer because the execution layer can consume verifiable state
instead of dashboards or inferred summaries.

## Machine-Readable Appendix

### Snapshot Schema

```json
{
  "snapshot_id": "string",
  "tenant_id": "string",
  "generated_at": "RFC3339 UTC Z string",
  "snapshot_version": "string",
  "source_authorities": [
    {
      "authority": "string",
      "available": true,
      "entity_count": 0,
      "relationship_count": 0,
      "source_tables": ["string"],
      "source_routes": ["string"],
      "produced_entity_types": ["string"]
    }
  ],
  "authority_graph": {
    "authorities": [
      {
        "authority": "string",
        "available": true,
        "ownership": "string",
        "source_tables": ["string"],
        "source_routes": ["string"],
        "capabilities": ["string"],
        "produced_entity_types": ["string"],
        "consumed_entity_types": ["string"],
        "downstream_dependencies": ["string"]
      }
    ],
    "dependencies": [
      {
        "authority": "string",
        "downstream_authority": "string",
        "relationship_type": "string"
      }
    ]
  },
  "entities": ["GovernanceDigitalTwinEntity"],
  "relationships": ["GovernanceDigitalTwinRelationship"],
  "baselines": ["GovernanceDigitalTwinBaselineReference"],
  "replay_safe_export": "object",
  "fingerprint": "sha256 hex",
  "redaction_profile": "replay_safe",
  "completeness": "object",
  "warnings": ["string"],
  "limitations": ["string"]
}
```

### Entity Schema

```json
{
  "id": "string",
  "type": "policy|control|evidence|finding|remediation|assessment|report|decision|workflow|simulation|replay|customer|framework|authority",
  "authority": "string",
  "source_ref": "string",
  "title": "string",
  "status": "string",
  "created_at": "RFC3339 UTC Z string",
  "updated_at": "RFC3339 UTC Z string",
  "confidence": 0,
  "tenant_scope": "string",
  "replay_safe": true,
  "redaction_state": "string",
  "metadata_hash": "sha256 hex"
}
```

### Relationship Schema

```json
{
  "id": "string",
  "type": "governs|verifies|maps_to|supports|contradicts|remediates|generated_from|published_to|decided_by|depends_on|supersedes|derived_from|affects|owned_by",
  "from_entity_id": "string",
  "to_entity_id": "string",
  "authority": "string",
  "confidence": 0,
  "evidence_refs": ["string"],
  "created_at": "RFC3339 UTC Z string",
  "replay_safe": true,
  "metadata_hash": "sha256 hex"
}
```

## Lineage, Identity, and Manifest

Snapshots now carry:

- `parent_snapshot_id`
- `previous_fingerprint`
- `generation`
- `lineage_id`
- `category`
- `graph_schema_version`
- `builder_version`
- `twin_identity`
- `manifest`
- `validation_report`
- `state_extensions`
- `future_references`

The manifest is deterministic and acts as the audit envelope. It includes schema versions, entity/relationship/authority counts, completeness score, fingerprint, redaction profile, baseline reference, builder version, MCIM version, export version, validator version, lineage, and generation. The manifest itself is also canonicalized and stored through immutable mappings.

## Validation Shell

The builder and validator are now separate concerns. The build flow is:

1. Construct deterministic snapshot state
2. Run structural validation
3. Compute fingerprint
4. Build manifest
5. Build replay-safe export
6. Run replay-integrity validation

Validator invariants include, with structured `INFO`, `WARNING`, `ERROR`, and `FATAL` severity findings:

- no orphan relationships
- no duplicate entity IDs
- no duplicate relationship IDs
- hash uniqueness
- required root authorities present
- no circular authority chains in the structural dependency graph
- relationship cardinality checks for single-target relationship classes
- replay integrity across snapshot ID, manifest, and replay-safe export

## MCIM Registration

The foundation now consumes explicit MCIM registrations from the shared registration manifest for:

- twin
- snapshot
- manifest
- baseline
- authority graph
- relationship graph
- export
- validator

## Completeness Model

Completeness is now formalized as deterministic structured metadata:

- coverage
- missing authorities
- missing sources
- partial state
- unavailable sources
- confidence in completeness

## Confidence and Provenance

Every entity carries deterministic provenance:

- origin authority
- source table
- source object
- capture method
- deterministic extractor
- created-from references

Every entity and source authority also carries deterministic confidence provenance metadata:

- authority
- confidence weight
- coverage percent
- freshness anchor
- trust level
- computation method
