# Signed Validation Manifests

Every CI gate run in FrostGate produces a **validation manifest** — a small,
canonical JSON record that captures exactly what was validated, on which
inputs, and (optionally) is signed with Ed25519 so downstream systems can
detect tampering.

## Why

`RuntimeResult` records *how long* a gate took and *what it saw*. A signed
manifest layers on top:

- an immutable identity (SHA-256 over canonical content),
- a cryptographic proof that the run was produced by an authorized signer,
- a hash chain so consecutive manifests can be verified as a linked ledger,
- and an artifact hash map that ties external files to the run.

## Artifact layout

```
artifacts/ci/manifests/
├── fg-fast.manifest.json     # per-gate manifests
├── fg-security.manifest.json
├── verification.json         # latest verification outcome (advisory)
└── chain.json                # ordered list of manifest hashes
```

## Manifest structure

`ValidationManifest` is a frozen dataclass; fields are all `str` or
`dict[str, str]` so serialization stays byte-stable. Key fields:

| Field                    | Purpose                                        |
| ------------------------ | ---------------------------------------------- |
| `manifest_id`            | SHA-256 hex of canonical content               |
| `manifest_hash`          | Same as `manifest_id` (equality by design)     |
| `previous_manifest_hash` | Hash-chain link to prior manifest ("" = root)  |
| `gate`                   | `fg-fast` \| `fg-security` \| ...              |
| `commit_sha`, `tree_sha` | Repo identity                                  |
| `dependency_fingerprint` | Deterministic hash of pinned deps              |
| `runtime_result_hash`    | SHA-256 of canonical `RuntimeResult` JSON      |
| `artifact_hashes`        | `path -> sha256hex` for auxiliary files        |
| `validation_status`      | `passed` \| `failed` \| `skipped`              |
| `signature_algorithm`    | `ed25519` \| `unsigned`                        |
| `signature`              | 64-byte Ed25519 sig (hex, 128 chars)           |
| `signing_identity`       | 16-char key ID = `sha256(pub)[:16]`            |
| `verification_status`    | `verified` \| `unsigned` \| `failed` \| `pending` |

### Canonicalization

Hashes and signatures are computed over `canonical_bytes(manifest_dict)`:

- `sort_keys=True, separators=(",", ":"), ensure_ascii=True`
- Fields excluded from the pre-image: `manifest_id`, `manifest_hash`,
  `created_at`, `signature`, `signature_algorithm`, `signing_identity`,
  `verification_status`.

Excluding the signing fields is essential — the signature is computed over
the *same* pre-image as the hash, so signing must not alter the pre-image or
`verify_hash` would break after `sign_manifest`.

## Trust model

- **Signer key** — the runner holds an Ed25519 private key in
  `FG_MANIFEST_SIGNING_KEY` (32 raw bytes, hex-encoded). If the variable is
  unset, `create-manifest` produces an unsigned manifest — verification of
  unsigned manifests is intentionally non-fatal so existing artifacts keep
  loading.
- **Verifier key** — consumers hold the corresponding public key in
  `FG_MANIFEST_VERIFY_KEY` (or pass `--key <hex>` on the CLI). Verification
  never crashes on bad input; it returns a structured `VerificationResult`.
- **Rotation** — keys can be rotated by generating a new pair
  (`generate_keypair()`); the `signing_identity` field pins each manifest
  to the exact public key that produced it, so verifiers can select the
  correct key from a rotation set.

## Signature lifecycle

1. `build_manifest(result, gate, ...)` produces an unsigned manifest with
   `manifest_hash` computed.
2. `sign_manifest(manifest, provider)` returns a copy with `signature`,
   `signing_identity`, and `signature_algorithm="ed25519"` filled in. The
   manifest hash does **not** change.
3. `write_manifest(manifest)` writes canonical JSON to
   `artifacts/ci/manifests/<gate>.manifest.json`.
4. Downstream verification calls `verify_manifest(manifest, public_key_hex,
   previous, result)` and receives a dict of check-name to
   `VerificationResult`. Any consumer can treat "all checks valid" as
   `verified`.

## CLI

The runtime intelligence CLI exposes signed-manifest subcommands:

```bash
python tools/testing/runtime_intelligence/cli.py create-manifest \
    --gate fg-fast --status passed

python tools/testing/runtime_intelligence/cli.py sign-manifest \
    --manifest artifacts/ci/manifests/fg-fast.manifest.json

python tools/testing/runtime_intelligence/cli.py verify-manifest \
    --manifest artifacts/ci/manifests/fg-fast.manifest.json \
    --key "$FG_MANIFEST_VERIFY_KEY"

python tools/testing/runtime_intelligence/cli.py validate-chain \
    --manifest-dir artifacts/ci/manifests

python tools/testing/runtime_intelligence/cli.py verify-runtime --gate fg-fast
python tools/testing/runtime_intelligence/cli.py print-manifest --manifest <path>
python tools/testing/runtime_intelligence/cli.py export-manifest --manifest <path> --output <path>
```

The pre-existing `--gate` invocation (recording a runtime result) is
unchanged; the dispatch happens ahead of `argparse` in `main()`.

## Future KMS integration

`Ed25519KeyProvider` is intentionally a thin abstraction:

- Today: `from_env()` reads raw hex-encoded keys from environment variables.
  Sufficient for CI runners with rotate-on-deploy semantics.
- Next: swap `from_env()` for a `from_kms(kms_key_id)` variant backed by
  AWS KMS, GCP KMS, or an in-cluster HSM. The signing surface
  (`provider.sign(data)`) already assumes a black-box signer, so no
  callers need to change.
- Later: attach a transparency-log receipt (Sigstore Rekor) alongside the
  signature so third parties can verify the manifest without holding the
  public key directly.

## Security invariants (enforced by tests)

- Private key bytes never appear in `repr`, `str`, serialized manifest,
  verification result, or history entries.
- `verify_signature_bytes` never raises on bad input — all failures
  surface as structured results.
- Hash pre-image is stable under `sign_manifest`; re-signing produces
  identical signatures (Ed25519 is deterministic).
- Unknown fields in serialized manifests do **not** break
  `manifest_from_dict` — forward compatibility is asserted in the test
  suite.
