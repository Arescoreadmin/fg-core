# Client Letter Templates

Six templates covering the full engagement lifecycle. Fill every `[PLACEHOLDER]` before sending.

| # | File | When to send | Requires signature |
|---|------|-------------|-------------------|
| 1 | `1_engagement_proposal.md` | Before engagement is scheduled | No |
| 2 | `2_authorization_letter.md` | With the proposal — client signs before session | Yes (client + you) |
| 3 | `3_data_handling_notice.md` | With the proposal — informational, no signature needed | No |
| 4 | `4_report_delivery.md` | Within 24 hrs of session, when report is in portal | No |
| 5 | `5_remediation_followup_30day.md` | Exactly 30 days after report delivery | No |
| 6 | `6_engagement_closeout.md` | All critical/high resolved, or at 90-day portal expiry | No |

## Sending sequence

```
Schedule engagement
       │
       ▼
Send #1 (Proposal) + #2 (Authorization) + #3 (Data Notice)
       │
       ▼ Client signs #2 and returns it
Session runs
       │
       ▼ Within 24 hours
Send #4 (Report Delivery) with portal URL + password
       │
       ▼ 30 days later
Send #5 (Follow-Up) — check portal first for resolved count
       │
       ▼ All critical/high resolved or 90-day expiry
Send #6 (Close-Out)
```

## Placeholders reference

| Placeholder | Where to find it |
|-------------|-----------------|
| `[CLIENT_ORG]` | Client's legal organization name |
| `[CLIENT_CONTACT_NAME]` | Primary contact name |
| `[CLIENT_CONTACT_TITLE]` | Their title |
| `[DATE]` | Today's date |
| `[ENGAGEMENT_DATE]` | Date of the assessment session |
| `[ENGAGEMENT_ID]` | The engagement ID from the FrostGate console |
| `[PRICE]` | Your quoted price (Snapshot: $299–999) |
| `[PORTAL_PASSWORD]` | The `PORTAL_PASSWORD` env var value — share securely, not plaintext |
| `[PORTAL_EXPIRY_DATE]` | 90 days from engagement date |
| `[DATA_EXPIRY_DATE]` | Same as portal expiry |
| `[PHONE]` | Your direct phone number |
| `[TOTAL_FINDINGS]` / `[CRITICAL_COUNT]` etc. | From the portal Risk Posture Dashboard |
| `[ORIGINAL_COVERAGE]` / `[CURRENT_COVERAGE]` | NIST coverage % from portal Coverage page |
