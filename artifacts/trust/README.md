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

**Never commit:** tokens, AppRole secret IDs, private key material, or any value matching
the secret field pattern in `services/cgin/key_management/trust_evidence.py`.

## Secret scanner coverage

Files in this directory are covered by two independent guards:

1. **`codex_gates.sh` secret scan** — runs on all committed files (no exclusion for
   `artifacts/trust/`). Catches PEM private key markers, AWS secret access keys, and
   Slack tokens. Run via `make fg-fast` and in CI.

2. **`trust_evidence._contains_secret_field()`** — semantic field-name scanner executed by
   `validate_manifest()`. Catches field names matching `token`, `secret_id`, `private_key`,
   `authorization`, `bearer`, `recovery_key`, `unseal` anywhere in the manifest object
   graph. Any manifest committed here must pass `validate_manifest()` before use.

Prose instructions alone are not a technical control. These two guards are.

The `check_no_plaintext_secrets.py` pre-commit hook scans `.env` files only; it does not
scan `artifacts/trust/`. `codex_gates.sh` closes that gap for this directory.

## Tooling

```bash
# Validate the ceremony evidence manifest
python tools/customer_zero_trust_evidence.py validate artifacts/trust/customer_zero_trust_evidence.json

# Inspect the manifest (human-readable summary)
python tools/customer_zero_trust_evidence.py inspect artifacts/trust/customer_zero_trust_evidence.json

# Verify public key anchors are consistent
python tools/customer_zero_trust_evidence.py verify-anchors artifacts/trust/customer_zero_trust_evidence.json
```

The manifest JSON is assembled manually during the production ceremony — there is no `init` subcommand. The ceremony runbook in `docs/deployment/customer_zero_trust_deployment_contract.md` provides the required field list.

## Recovery state

See `docs/deployment/customer_zero_trust_recovery.md` for the full recovery procedure.

The `RECOVERY` dimension in the evidence manifest reaches `PASS` only after an actual recovery drill is executed and a `recovery_drill_<date>.json` record is committed here.
