# MSP-007 evidence sharing

This document covers what a customer shares with an MSP, what the MSP receives, and how each side can prove what happened.

## What is shared

A share covers exactly one released report version, identified by three things:

- `report_id`: the `governance_reports` row;
- `report_version`: the per-engagement version number;
- `manifest_hash`: the SHA-256 fingerprint of the canonical report document.

The customer passes the fingerprint it reviewed. If the report changed in the meantime, the share is refused with `MSP_REPORT_FINGERPRINT_MISMATCH`.

## What the MSP receives

| Read | Contents |
|---|---|
| Share list | Status, version, fingerprint, expiry, live access state with blockers, next actions |
| Verify | Lifecycle facts, integrity results, provenance summary (decision, snapshot fingerprint, evidence count, source authentication), evidence reference identifiers |
| Download | The canonical report document (`report_json`) with its fingerprint, signature, signature kind, integrity results and lifecycle |

## What the MSP never receives

- Raw evidence or scan payloads;
- interview material;
- credentials or secrets;
- other reports, including other versions of the same engagement;
- drafts;
- the customer's people;
- other customers' data;
- audit records beyond its own chain.

## Lifecycle facts

Each fact is reported separately, from its own canonical source, as defined in `MSP_007_AUTHORITY_AUDIT.md`:

- generated;
- QA approved;
- independent human QA;
- production qualified;
- released (FINAL);
- delivery authorized;
- delivered.

A report can be QA-approved and still not released. A report can be released without being delivered.

## Integrity vocabulary

| Value | Meaning |
|---|---|
| `HASH_VERIFIED` | The stored fingerprint matches a fresh SHA-256 of the current report content |
| `SIGNATURE_VERIFIED` | The report signature verified: the FrostGate trust binding (Vault Transit) or the legacy FrostGate Ed25519 signature, as shown by `signature_kind` |
| `AUDIT_CHAIN_VERIFIED` | The evidence chain behind the report verified (provenance `chain_valid`) |
| `VERIFICATION_UNAVAILABLE` | Not checked: unsigned, key unavailable, or content already failed |
| `VERIFICATION_FAILED` | The check ran and failed. Reads fail closed |

These are FrostGate's own verifications. They are not third-party notarization or external certification.

## How a partner verifies independently

The downloaded document carries the canonical `report` object and its `manifest_hash`. Anyone can recompute the fingerprint:

```
sha256(json.dumps(report, sort_keys=True, separators=(",", ":"), ensure_ascii=True))
```

The result must equal `manifest_hash`; this is the same serialization the signing path uses. Signature verification additionally needs FrostGate's public key material, and offline signature verification is not packaged in MSP-007.

## Revocation semantics

- **Immediate for future reads:** a revoked or expired share blocks the next verify or download, and the next list shows it blocked.
- **No recall:** revocation cannot recall a document already downloaded.
- **History preserved:** the share row and every event remain, and the access history survives revocation (t12, demonstration step 14).

## Billing

Sharing, verifying and downloading record no usage. MSP-006 delivery remains the only charge (t38).
