# FrostGate Canonical Prompt Templates

These templates operate against:

- `artifacts/audits/canonical_roadmap/FROSTGATE_CANONICAL_ROADMAP.md`
- `artifacts/audits/canonical_roadmap/roadmap_manifest.json`
- `artifacts/audits/canonical_roadmap/EXECUTION_STATE.json`

## Templates

| File | Use |
|---|---|
| `01_IMPLEMENTATION.md` | Build only the current PR |
| `02_VALIDATION.md` | Validate the current PR without expanding scope |
| `03_AUDIT.md` | Audit repository and execution-system drift |
| `04_ARCHITECTURE.md` | Review a material architecture decision |
| `05_INCIDENT.md` | Contain and recover from production/security incidents |
| `06_ROADMAP_EVOLUTION.md` | Modify the roadmap only when verified reality requires it |

## Rule

No feature is allowed to exist unless it moves the current PR toward the current Revenue Gate and ultimately toward the next paying customer.
