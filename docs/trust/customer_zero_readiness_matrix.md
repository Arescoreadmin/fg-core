# CUSTOMER-ZERO-TRUST-001 — Readiness Matrix

**Authority:** `customer_one/roadmap_authority.yaml` — CUSTOMER-ZERO-TRUST-001 is NEXT.
**Base SHA:** `c5f29583a105ce2028fd3197f7f03b61e593753d`.
**Branch:** `feat/customer-zero-trust-ceremony-readiness`.
**Classification legend:**
- **COMPLETE** — repo/captured evidence actually proves it.
- **LOCAL_PASS_LIVE_PROOF_REQUIRED** — passes locally, awaits a live provider.
- **LIVE_PROOF_REQUIRED** — cannot be proven without live infrastructure.
- **HUMAN_AUTHORIZATION_REQUIRED** — needs an explicit human gate.
- **BLOCKED** — has a dependency blocker.

## 1. Stream status

| # | Stream | State | Evidence |
|---|---|---|---|
| 1 | Trust implementation audit | COMPLETE | `docs/trust/customer_zero_trust_authority_graph.md`; no defects requiring repair |
| 2 | Vault Transit ceremony definitions | LOCAL_PASS_LIVE_PROOF_REQUIRED | `infra/vault_transit.tf` (non-exportable, non-deletable, ed25519, pinned to the three Customer-Zero names); `tests/test_customer_zero_trust_terraform_safety.py` T5, T6 |
| 3 | Least-privilege role separation | LOCAL_PASS_LIVE_PROOF_REQUIRED | `infra/vault_policies.tf` + `infra/vault_approle.tf`; `test_customer_zero_trust_terraform_safety.py` T7, T8, T8b. Live `terraform apply` + Vault policy enforcement is the LIVE_PROOF. |
| 4 | Public trust anchor enrollment | LOCAL_PASS_LIVE_PROOF_REQUIRED | `services/cgin/key_management/trust_evidence.py` schema + `tools/customer_zero_trust_evidence.py` validator; `artifacts/trust/README.md`; live anchor values populated at ceremony §J. |
| 5 | Canonical signature envelope | COMPLETE | `services/governance/trust_binding.py:SignatureEnvelope` + pre-crypto guards; `tests/test_customer_zero_trust_ceremony_readiness.py` C1–C5, H2 |
| 6 | Operational negative test suite | COMPLETE | `tests/test_customer_zero_trust_ceremony_readiness.py` A1–A9 (role substitution), B1–B6 (forbidden signers), F1–F5 (fail-closed), G1–G4 (anchor-only verify), H1–H4 (secret boundary) |
| 7 | Rotation + historical verification | LOCAL_PASS_LIVE_PROOF_REQUIRED | `tests/test_customer_zero_trust_ceremony_readiness.py` E1–E3; LIVE_PROOF via `infra/docs/ceremony-runbook.md` CHECKPOINT P (rotate + historical verify + post-rotation sign) |
| 8 | Failure / recovery ceremony | LOCAL_PASS_LIVE_PROOF_REQUIRED | `tests/test_customer_zero_trust_ceremony_readiness.py` F1–F5 (fail-closed on vault-down / malformed / tampered); LIVE_PROOF via CHECKPOINT R (offline verify + recovery drill) |
| 9 | Ceremony evidence system | COMPLETE | `services/cgin/key_management/trust_evidence.py` (schema + validator + secret scanner); `tests/test_customer_zero_trust_evidence.py` 25 tests; canonical JSON schema `schemas/artifacts/customer_zero_trust_evidence.schema.json` |
| 10 | Ceremony runner / runbook | COMPLETE | `infra/docs/ceremony-runbook.md` 22 checkpoints (A–U) with explicit human gates, secret boundaries, stop conditions, and cost checkpoints; the 2026-10-02 live partial-apply iteration validated it empirically. |
| 11 | Cost safety | HUMAN_AUTHORIZATION_REQUIRED | `infra/docs/cost-authorization.md`; CHECKPOINT D + U; prior PR #737 shipped the operator cost-authorization evidence as `COST_READY_FOR_OPERATOR_AUTHORIZATION`. |
| 12 | Terraform safety | COMPLETE | `tests/test_customer_zero_trust_terraform_safety.py` T1–T15 (prevent_destroy on all irreplaceable resources, no credential-producing resources, no literal secret markers, Ed25519 pinned, AppRole deny-default, policy deny admin paths, outputs non-sensitive, provider versions pinned, HCP Terraform remote state, scoped IAM audit policy, lock file committed); `terraform fmt -check` rc=0 |
| 13 | Customer-Zero acceptance handoff | COMPLETE (contract defined) | `docs/trust/customer_zero_acceptance_handoff.md`; the `SIGNED_PROOF` dimension in CUSTOMER-ZERO-ACCEPT-001 is cleanly bounded to verifying — never fabricating — the three governance envelopes against the enrolled public anchors. |
| 14 | Moat review | COMPLETE | `docs/trust/customer_zero_moat_review.md` |

## 2. CUSTOMER-ZERO-TRUST-001 completion-evidence contract

Four requirements per `customer_one/roadmap_authority.yaml`:

| Requirement | Current state | What is still needed |
|---|---|---|
| three distinct managed trust roles and stable key IDs | LOCAL_PASS_LIVE_PROOF_REQUIRED | Live Vault Transit mount with three Ed25519 keys named `customer-zero-{identity,acceptance,approval}` and key_version=1 captured in the evidence manifest. |
| canonical identity assertion and bounded acceptance entitlement issuance | COMPLETE (envelope schema) + LIVE_PROOF_REQUIRED (live signing) | Live `transit/sign/customer-zero-identity` and `transit/sign/customer-zero-acceptance` probes producing `vault:v1:` envelopes recorded in the evidence manifest. |
| non-exportable approval signing and public-only verification | COMPLETE (schema + offline verify path) + LIVE_PROOF_REQUIRED (live signing) | Live `transit/sign/customer-zero-approval` probe + enrolled public anchor; `TrustAnchor.verify()` validation against the live-captured public key. |
| historical verification, durable provenance, and operational fail-closed tests | COMPLETE (local) + LIVE_PROOF_REQUIRED (live rotation) | Live key rotation (CHECKPOINT P) producing `pre_rotation_sig` + `post_rotation_sig` with `historical_verify_rc=0`. |

## 3. Forbidden scope (per authority YAML)

The following remain explicitly out of scope for CUSTOMER-ZERO-TRUST-001 and are not touched by this readiness PR:
- PROD-QUAL-001 (merged)
- GOV-DELIVERY-001 (merged)
- generalized PKI, IAM, RBAC, or secrets-platform redesign
- Customer-Zero corpus or expected-outcome changes

## 4. Live ceremony remainder

Everything below requires live HCP + AWS + explicit human gates. None of it can be performed in a $0 PR.

| Gate | Owner | Evidence target |
|---|---|---|
| Cost authorization | Human operator | signed cost-authorization record (CHECKPOINT D) |
| Explicit terraform-apply authorization | Human operator | written statement (CHECKPOINT E) |
| HCP cluster provisioning (Phase 1 apply) | Operator + `terraform apply` | Terraform state + outputs (`vault_address`, cluster ID) |
| Admin token bootstrap | Human operator | token accessor only (CHECKPOINT G) |
| Vault resource provisioning (Phase 2 apply) | Operator + `terraform apply` | 11 Vault resources, Transit keys, policies, AppRoles |
| Public anchor collection | Operator | three Ed25519 public keys, fingerprints |
| AppRole SecretID → Railway transfer | Human operator (SECRET BOUNDARY) | Railway Variables tab confirmation (no values exposed) |
| Positive signing probes (per role) | Operator (vault CLI via AppRole) | `vault:v1:` signatures per role |
| Cross-role negative probes | Operator | 403/permission denied for off-diagonal attempts |
| Key rotation + historical verify (identity key) | Operator | `pre_rotation_sig` + `post_rotation_sig` + `historical_verify_rc=0` |
| CloudWatch audit stream | Operator (HCP UI) | AWS access key entered in HCP UI; log group events observed |
| Evidence manifest finalization | Operator | manifest `state=PASS`, fingerprint committed |
| Cluster disposition (destroy for cost safety) | Human operator | Terraform state cleaned; retained public anchors committed |

## 5. $0 budget confirmation

This readiness PR performs no live mutation. Specifically:
- No `terraform apply`, no `terraform destroy`, no saved plan execution.
- No HCP, AWS, or Vault API calls.
- No AppRole SecretID generation or consumption.
- No live credentials rotated.
- No modifications to AWS, HCP, or Railway resources.

Static checks only (`terraform fmt -check` is read-only). Tests run against the local `TrustBindingFake` in-process; no network I/O.

## 6. Final determination

**PRODUCTION_CEREMONY_NOT_READY** — correctly, because the live ceremony has not yet been executed. The readiness pass is **COMPLETE**: when paid HCP Vault infrastructure is next created, the operator will be **executing** a prepared, tested, bounded ceremony, not **designing** it.

Pre-provisioning gates that remain are precisely the gates the project doctrine demands be gated by human authority: cost, destructive authorization, and secret-entry boundaries.
