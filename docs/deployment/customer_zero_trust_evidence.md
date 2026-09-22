# Customer-Zero operational trust evidence

This validator defines the non-secret evidence that an external HCP Vault ceremony must return before `CUSTOMER-ZERO-TRUST-001` can be reconciled. It does not provision Vault, create keys or credentials, call mutation APIs, or execute Customer-Zero acceptance.

## Evidence contract

A JSON manifest contains source/deployment provenance, Vault deployment identity, three role records, public anchors, policy fingerprints, audit references, rotation/failure/recovery evidence references, and dimension states. The canonical fingerprint is SHA-256 over canonical JSON with the self-referential `evidence_fingerprint` field removed. Semantically unordered role/anchor/evidence lists are sorted before hashing.

Each role must be exactly one of `customer-zero-identity`, `customer-zero-acceptance`, or `customer-zero-approval`, with distinct runtime identity, policy fingerprint, Transit key ID, Ed25519 metadata, `exportable=false`, `deletion_allowed=false`, active key version, and matching public-anchor metadata.

Secret-bearing fields—including token, SecretID, private key, authorization, bearer, recovery, and unseal material—are rejected, not redacted. `public_key` is permitted. Validation is offline and requires no network access.

## Commands

```text
.venv/bin/python tools/customer_zero_trust_evidence.py inspect <manifest> --json
.venv/bin/python tools/customer_zero_trust_evidence.py fingerprint <manifest>
.venv/bin/python tools/customer_zero_trust_evidence.py validate <manifest> --json
.venv/bin/python tools/customer_zero_trust_evidence.py verify-anchors <manifest> --json
.venv/bin/python tools/customer_zero_trust_evidence.py verify-role-separation <manifest> --json
.venv/bin/python tools/customer_zero_trust_evidence.py verify-provenance <manifest> --json
.venv/bin/python tools/customer_zero_trust_evidence.py verify-complete <manifest> --json
```

The result is deterministic: `FAIL` dominates `NOT_PROVEN`, which dominates `PASS`. Missing deployment, audit, recovery, rotation, or failure evidence remains `NOT_PROVEN`; unsafe configuration, mismatches, secret-bearing fields, and source/deployment conflicts are `FAIL`. A validator PASS is not Customer-Zero acceptance, PROD-QUAL, or GOV-DELIVERY.

The ceremony state machine is evidence-gated and cannot skip states. Real operators must provision HCP Vault externally, collect non-secret evidence, enroll anchors explicitly, record role-substitution/rotation/failure tests, and retain the resulting manifest.
