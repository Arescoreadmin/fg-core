# MSP-007 operator guide

This guide is for FrostGate operators and the customer and partner administrators they support. MSP-007 adds no platform-operator route: sharing is entirely a decision between the customer and the MSP.

## Prerequisites (per environment)

1. **Migration 0209 applied** (`msp_report_shares`, forced RLS).
2. **MSP-001, MSP-002, MSP-003 prerequisites in place:**
   - the MSP is designated;
   - it has the `msp.multi_tenant` entitlement;
   - its staff are bound members;
   - the internal gateway secret is configured.
3. **A relationship that delegates `report.read`.** The customer grants it when approving the relationship on `/partners`.
4. **A released report.** Field Assessment must have produced a FINAL report through independent QA, version approval and production qualification. MSP-007 cannot make a report FINAL.

None of these is evidenced in any deployed environment.

## Customer administrator (`/partners`)

- **Your reports and their status:** every report version with its separate lifecycle facts and integrity. A report that cannot be shared shows why.
- **Share a report:**
  1. Choose the partner, a released report and the number of days (1 to 90).
  2. Confirm against the exact version and fingerprint shown.
- **Requests from your partners:** choose a released version of the requested engagement and share it, or decline.
- **Shared reports:** revoke at any time. **Access history** shows every view, download and refused attempt, the partner account involved, and whether your audit chain verifies.

## MSP administrator (`/msp`, after selecting a customer)

- **Reports shared by this customer**, in four groups:
  - available;
  - shared but not available now (with the reason);
  - awaiting the customer;
  - ended.
- **Verify:** re-checks the report now and shows fingerprint, signature and evidence-chain results.
- **Download:** saves the canonical report document. The customer sees the download in its history.
- **Ask for a report:** shown for assessments you started under an approved MSP-003 grant. The customer decides.

## Support: when a partner cannot open a shared report

The API and the Console return a blocker code:

| Blocker | Who acts |
|---|---|
| `SHARE_PENDING_CUSTOMER`, `SHARE_EXPIRED`, `SHARE_REVOKED`, `SHARE_REJECTED` | The customer |
| `RELATIONSHIP_NOT_DELEGATING_REPORT_READ`, `RELATIONSHIP_INACTIVE` | The customer (relationship on `/partners`) |
| `CUSTOMER_TENANT_INACTIVE` | The platform (tenant lifecycle) |
| `REPORT_NOT_RELEASED`, `REPORT_VERSION_CHANGED`, `REPORT_UNAVAILABLE` | The customer and its assessment team (release a version, share the current one) |
| `REPORT_INTEGRITY_FAILED`, `SIGNATURE_FAILED`, `EVIDENCE_CHAIN_FAILED`, `TRUST_ENFORCEMENT_BLOCKED` | **Security incident:** content or evidence no longer verifies. Preserve the records; do not repair data in place. The refusal is already recorded on both chains and in the engagement trail |
| 403 on every call | The MSP's designation, membership or entitlement was removed |

## Incident: revoke all partner access to reports

- **One share:** the customer revokes it on `/partners`.
- **Every share of one partner:** the customer suspends or revokes the relationship. Every share stops at once, because reads require an active relationship that delegates `report.read`.
- **Every customer of one partner:** the platform suspends the MSP organization (MSP-001).

None of these deletes history.
