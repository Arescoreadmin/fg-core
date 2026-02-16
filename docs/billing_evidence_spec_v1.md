# Billing Evidence Spec v1

## Spec ID
- `billing_evidence_spec_version`: `v1`
- Backward compatibility rule: verifier must reject unknown versions unless explicitly upgraded.

## Required bundle files
- `manifest.json`
- `invoice.json`
- `daily_counts.json`
- `coverage_proof.json`
- `server_build_info.json`
- `verification.txt`
- `attestation.sig`
- `attestation.pub`

## Manifest contract
Required fields:
- `billing_evidence_spec_version`
- `invoice_id`
- `tenant_id`
- `pricing_hash`
- `contract_hash`
- `config_hash`
- `policy_hash`
- `coverage_day_rule`
- `invoice_period_boundary`
- `verifier_version`
- `expected_pubkey_kid`
- `files[]` with `path`, `sha256`, `size`

## Verifier output contract
`scripts/fg_billing_verify.py` emits:
- `PASS: billing evidence bundle verified` and `REASON_CODES: []`
- OR `FAIL: ...` and a non-empty `REASON_CODES: [...]`

## Offline verification command
```bash
python scripts/fg_billing_verify.py <bundle_dir> --pubkey <bundle_dir>/attestation.pub
```

## Build/schema fingerprint requirements
`server_build_info.json` includes:
- `git_sha`
- `service_version`
- `python_version`
- `schema_migrations`
- `schema_hash`
- `verifier_version`
- `expected_pubkey_kid`
