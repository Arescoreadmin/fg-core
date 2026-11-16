# MSP-007 security model

**Tests:**

- `tests/security/test_msp_007_report_sharing.py`, named `tNN` after the acceptance matrix, plus the end-to-end demonstration.
- `tests/test_migrations_postgres_replay.py::test_0209_msp_007_report_shares_are_isolated_by_forced_rls` (CI Postgres).
- `apps/console/tests/msp-007-console.test.js`.

## Principles

- **The customer owns the evidence.** A share is the customer's own decision, made by its canonical `tenant_admin`. It covers one exact report version, for at most 90 days and never longer than the relationship. Only the customer can create or end one.
- **Nothing else grants report access.** These do not grant access on their own (t03, t04, t05, t32):
  - an MSP-001 relationship;
  - an MSP-003 assessment grant;
  - an MSP-006 payer assignment;
  - knowledge of a report id, share id or fingerprint.
- **Only released content is shared.** The canonical release decision must say FINAL at share time and again at every read (t09–t11, t37). A report that loses FINAL is no longer readable, whatever the share says. Causes include changed evidence and a changed qualification.
- **Version-bound.** The share stores report id, version and fingerprint:
  - A new report version is not covered (t28).
  - A changed stored fingerprint blocks the share (t29).
  - Content that no longer matches its fingerprint blocks the share (t26).
- **The MSP-001 ceiling is unchanged.** Reads use the existing `report.read` delegation. MSP-007 adds no permission and widens no ceiling.

## Effective authority for an MSP read

| Dimension | Check | Test |
|---|---|---|
| MSP designation active | `resolve_msp_membership` → `msp_organization_active` | t15 |
| MSP actor | Bound, active membership; the role holds `report.read` | t16 |
| MSP entitlement | `require_capability("msp.multi_tenant")` | t14 |
| Relationship | Active, delegating `report.read`, and the same relationship the share was made under | t17b, t11d |
| Share | Active and unexpired | t12, t13, t47 |
| Customer tenant | `lifecycle_state == "active"` and kind `customer` | t17 |
| Exact report | Same id, version and fingerprint | t27, t28, t29 |
| Released | `_authoritative_report_state == FINAL` | t09–t11, t37 |
| Integrity | Content `HASH_VERIFIED`; signature not failed; evidence chain not failed; the export trust gate for download | t25, t26 |

## Separation of duties

- Only the customer's `tenant_admin` shares, approves, rejects or revokes.
  - An MSP actor gets `MSP_APPROVAL_REQUIRES_CUSTOMER` (t08).
  - Read-only roles get 403 (t48).
- A customer administrator who also holds any MSP membership gets `MSP_SELF_APPROVAL_DENIED` (t08). The requester of an MSP request cannot approve it.
- An MSP can request, withdraw its own request, verify and download. It has no approval, QA or delivery route. Canonical QA rules are unchanged (t37b).

## Isolation

- **API:** shares load only for one of their two parties. Unknown and foreign ids return identical 404s (t18, t32). Listings are filtered to the caller's own side (t19, t20, t30).
- **Postgres:** forced RLS on `msp_report_shares` with the policy `tenant_id = ctx OR msp_tenant_id = ctx` in both `USING` and `WITH CHECK`. There is no empty-context bypass. The CI probe checks that:
  - each party sees its rows, and a third tenant or an empty context sees none;
  - a spoofed insert is refused;
  - a third tenant's revoke matches nothing;
  - two concurrent approvals let one win;
  - a duplicate active share and an unbound active share are refused.
- **Reads:** the report is read under the customer's RLS context. The MSP holds no copy; nothing is written to an MSP-owned location.

## Downloads

- **No URL or credential issued.** There is no presigned URL, storage credential or redirect: the bytes are returned by the authorized call.
- **Headers:**
  - `Cache-Control: no-store, private`;
  - `Content-Disposition: attachment`;
  - the version and fingerprint headers (t35).
- **Bounded:** downloads are limited to 10 MiB (t36). Identifiers are pattern-validated, so path-like values are rejected (t33).
- **Fail closed:** integrity or trust-gate failures fail closed. Such a failure is recorded on both chains (`tenant.msp.report_integrity_failed`) and in the customer's engagement trail (`report.access_denied`) without the content (t26).
- **Revocation scope:** revocation blocks every later call immediately. It cannot recall a copy the MSP already downloaded, and the product never claims otherwise.

## Audit and chain of custody

Events go to both parties' identity hash chains through `emit_msp_audit`:

- `tenant.msp.report_share_{requested, approved, rejected, withdrawn, revoked}`;
- `tenant.msp.report_{verified, downloaded, access_denied, integrity_failed}`.

Each event binds:

- actor and membership;
- MSP, customer and relationship;
- share, engagement and grant;
- report id, version and fingerprint;
- the expiry;
- previous and new state;
- the decision, and blockers where relevant;
- the integrity results;
- the correlation id and time.

Downloads also write `report.content_accessed` to the customer's engagement trail (t24).

The customer's share history shows the MSP account that read or tried to read its evidence (t40b). The MSP never sees the customer's people. Both chains verify after sharing, reads, revocation and refused reads (t43).

## Redaction

- Refusals return only `{code, blockers}` (t26, t34).
- Audit details pass the identity `safe_keys` allowlist: identifiers, fingerprints, decisions and codes. They contain no report content, evidence or contact emails.
- The verify summary lists evidence reference identifiers (at most 500), never evidence content.

## Remaining risks

- **Not deployed.** Migration 0209 is not applied anywhere, and Postgres RLS is proven only in CI Migrations Replay.
- **Downloaded copies.** Once downloaded, a copy is outside FrostGate's control, and revocation governs future access only.
- **Per-call cost.** Every MSP list row re-runs the canonical release decision, so large share lists are slower. Pages are bounded at 200.
- **Console audience.** Console access is `tenant_admin` only. Other MSP staff with `report.read` can use the API with a tenant-bound credential.
- **Expiry events.** Expiry is enforced on read. No event is written at the moment of expiry.
