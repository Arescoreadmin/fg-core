# Operator Runbook Index

The operational table of contents. When something happens, start here.

---

## By Event

| Event | Runbook | Location |
|---|---|---|
| **Production deploy** | Production Configuration Changes | `docs/operators/production_configuration_changes.md` |
| **Rollback** | Disaster Recovery | `docs/operators/disaster_recovery.md` |
| **Database backup** | Backup and Restore | `docs/operators/backup_restore.md` |
| **Backup automation / scheduling** | Backup Automation | `docs/operators/backup_automation.md` |
| **Backup schedule reference** | Backup Schedule | `docs/operators/backup_schedule.md` |
| **Database restore** | Backup and Restore §5 + Disaster Recovery | `docs/operators/backup_restore.md` |
| **Auth0 outage / identity failure** | Auth0 Roles + Disaster Recovery §escalation | `docs/operators/auth0_roles.md`, `docs/operators/disaster_recovery.md` |
| **Resend outage / email failure** | First Client Playbook §5 escalation; retry via `POST /portal/invitations` with same idempotency key | `docs/operators/FIRST_CLIENT_PLAYBOOK.md` |
| **Secret rotation** | Secret Rotation | `docs/operators/secret_rotation.md` |
| **Customer onboarding** | First Client Playbook | `docs/operators/FIRST_CLIENT_PLAYBOOK.md` |
| **Day-of pre-flight** | First Client Prep | `docs/operators/first_client_prep.md` |
| **Assessment scan execution** | Onboarding Runbook | `docs/operators/onboarding_runbook.md` |
| **Azure AD app setup (client)** | Azure AD App Setup | `docs/operators/azure_ad_app_setup.md` |
| **Credential delivery to client** | Credential Delivery | `docs/operators/credential_delivery.md` ⚠ rewrite pending (T14 — named-user path) |
| **Console usage** | Console User Guide | `docs/operators/console_user_guide.md` |
| **Incident response** | Disaster Recovery §escalation + First Client Playbook §8 | `docs/operators/disaster_recovery.md` |
| **Portal lockout (client cannot log in)** | First Client Playbook §8 escalation — same-day fix; if >4h deliver report by encrypted email | `docs/operators/FIRST_CLIENT_PLAYBOOK.md` |
| **Platform incident during engagement** | First Client Playbook §8 — phone client first, then email if their data or timeline affected | `docs/operators/FIRST_CLIENT_PLAYBOOK.md` |
| **Non-waivable-class event** | Stop engagement. Rollback. Founder communicates within 24h. See `LAUNCH_DECISION_RECORD.md` rollback trigger conditions. | `docs/governance/status/LAUNCH_DECISION_RECORD.md` |

---

## By Runbook

| Runbook | File | Last verified | Covers |
|---|---|---|---|
| Auth0 Roles | `auth0_roles.md` | — | Auth0 role configuration |
| Azure AD App Setup | `azure_ad_app_setup.md` | PR 25 | Client Azure AD app registration, scopes, admin consent |
| Backup and Restore | `backup_restore.md` | T1 (2026-07-30) | `pg_dump` method, restore to scratch, row-count verify |
| Backup Automation | `backup_automation.md` | T1.5 (2026-07-30) | `fg_backup.sh`, retention, offsite, signed manifests |
| Backup Schedule | `backup_schedule.md` | T1.5 (2026-07-30) | Schedule reference card |
| Console User Guide | `console_user_guide.md` | — | Console navigation, scan panels, report viewer |
| Credential Delivery | `credential_delivery.md` | ⚠ stale | Named-user portal invite; instructions predate named-user cutover |
| Disaster Recovery | `disaster_recovery.md` | T1.5 (2026-07-30) | RTO/RPO targets, rollback, full DR procedure, escalation |
| First Client Playbook | `FIRST_CLIENT_PLAYBOOK.md` | — | End-to-end engagement script (H1–H18 map) |
| First Client Prep | `first_client_prep.md` | T1.5 | Day-of pre-flight checklist |
| Onboarding Runbook | `onboarding_runbook.md` | PR 20 | All 9 connectors, before-meeting / in-meeting split |
| Production Configuration Changes | `production_configuration_changes.md` | — | Deploy, env var changes, Railway / Vercel procedures |
| Secret Rotation | `secret_rotation.md` | — | Top-5 blast-radius secrets, rotation procedure |

---

## Gaps (known; tracked in backlog)

| Gap | Severity | Notes |
|---|---|---|
| Incident runbook (timed drill) | Medium | Not yet executed — T8/T9 scope |
| `credential_delivery.md` rewrite | Low | Instructions predate named-user cutover (T14 plan item) |
| Portal lockout runbook (standalone) | Low | Currently embedded in First Client Playbook §8 |
| Auth0 outage escalation (standalone) | Low | Currently embedded in auth0_roles.md and disaster_recovery.md |

---

## Launch Governance Artifacts

These are not runbooks, but are referenced during and after launch:

| Artifact | File | Purpose |
|---|---|---|
| T5 Evidence | `docs/governance/status/T5_INFRASTRUCTURE_HEADROOM_EVIDENCE.md` | Infrastructure baseline + failure recovery proof |
| T6 Evidence | `docs/governance/status/T6_OPERATIONAL_REHEARSAL_EVIDENCE.md` | H1–H18 scripted dry run |
| Launch Readiness Review | `docs/governance/status/LAUNCH_READINESS_REVIEW.md` | Go/no-go synthesis before T6 |
| Launch Decision Record | `docs/governance/status/LAUNCH_DECISION_RECORD.md` | Immutable launch authorization |
| Execution State | `docs/governance/status/EXECUTION_STATE.md` | Current sprint state and blockers |
