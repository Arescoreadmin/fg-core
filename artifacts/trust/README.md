# Trust Evidence Artifacts

This directory holds the non-secret public verification material for CUSTOMER-ZERO-TRUST-001.

## Contents

| File | Description |
|------|-------------|
| `customer_zero_trust_evidence.json` | Canonical trust evidence manifest (created by the production ceremony) |
| `recovery_drill_<date>.json` | Recovery drill execution records (created after each drill) |

## What is stored here

Only non-secret material is committed to this directory:

- Public keys for the three Customer-Zero transit trust roles
- Public key fingerprints and key version bindings
- Ceremony metadata (ID, environment, operator identity, SHA bindings)
- Evidence dimension states and audit references
- Recovery drill records

**Never commit:** tokens, AppRole secret IDs, private key material, or any value matching the secret field pattern in `services/cgin/key_management/trust_evidence.py`.

## Tooling

```bash
# Validate the ceremony evidence manifest
python tools/customer_zero_trust_evidence.py validate artifacts/trust/customer_zero_trust_evidence.json

# Generate a new manifest skeleton (ceremony only)
python tools/customer_zero_trust_evidence.py init --ceremony-id <id> --environment <env>
```

## Recovery state

See `docs/deployment/customer_zero_trust_recovery.md` for the full recovery procedure.

The `RECOVERY` dimension in the evidence manifest reaches `PASS` only after an actual recovery drill is executed and a `recovery_drill_<date>.json` record is committed here.
