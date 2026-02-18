# Evidence Artifact Policy

## Policy Decision
Evidence artifacts under `artifacts/` are **generated** by CI/runtime and **should not be committed**, except explicit governance/static docs and approved baseline artifacts.

## Committed Artifacts (Allowlisted)
Committed artifacts are controlled by `tools/ci/artifact_policy_allowlist.json` and include:
- governance/static docs (`SOC_AUDIT_GATES.md`, additive plan docs)
- deterministic baseline inventory/survey outputs used for drift checks
- temporary legacy exception entries explicitly allowlisted until cleanup

## Generated Artifacts (Do Not Commit)
Generated evidence outputs include (non-exhaustive):
- `artifacts/*_evidence.json`
- `artifacts/anchor_receipts/*.json`

If present in git and not allowlisted, CI fails via `tools/ci/check_artifact_policy.py`.

## CI Storage + Integrity
- CI can regenerate evidence artifacts in workspace during jobs.
- Integrity is verified using schema validation and deterministic checks (`fg-contract`, artifact schemas, and evidence generators).
- Artifact policy is enforced as a security gate in Make/CI.

## Temporary Compatibility
If legacy committed evidence files exist, they must be explicitly allowlisted with rationale, then removed in a follow-up cleanup PR.
