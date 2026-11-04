# Client Onboarding Checklist

**Purpose:** Operator checklist for every FrostGate AI Governance Field Assessment engagement, from signed paper to 30-day close.
**Authority:** `docs/operators/FIRST_CLIENT_PLAYBOOK.md` (companion), `docs/commercial/founder_approval_checklist.md` (pre-collection gate)

---

## Pre-Engagement — Operator Side

Complete before scheduling the data collection session:

**Commercial:**
- [ ] Prospect qualified against ideal client profile (25–500 employees, Microsoft 365 / Entra ID, regulated-adjacent industry)
- [ ] Discovery call completed; disqualifiers confirmed absent
- [ ] Proposal sent (`docs/commercial/proposal_template.md`) with correct price, scope, and delivery note for report signing condition
- [ ] Proposal verbally accepted or written acceptance received
- [ ] Data Processing Agreement signed by both parties (`contracts/dpa_template.md`)
- [ ] Statement of Work signed by both parties (`docs/commercial/sow_template.md`)
- [ ] 50% upfront payment received (or 100% for design partner) — do not schedule the session until payment is confirmed
- [ ] Invoice issued and payment confirmed in bank/Stripe

**Founder approval gate (REQUIRED before proceeding):**
- [ ] `docs/commercial/founder_approval_checklist.md` completed and signed by Jason Cosat
- [ ] No production assessment evidence will be collected until all mandatory production controls are confirmed by founder

**Technical setup — operator:**
- [ ] Azure AD app registration instructions sent to client IT contact (`docs/operators/azure_ad_app_setup.md`)
- [ ] Client IT contact confirmed they received the instructions
- [ ] App registration scheduled (this is the long-lead item — start immediately after paper is signed; app registration must be complete before the session date)
- [ ] Tenant provisioned in FrostGate console (`console.frostgate.ai` → Admin → Tenants)
- [ ] Confirm portal key persisted (no `PERSISTENCE_UNAVAILABLE` in console logs)
- [ ] Engagement created in console with client name, domain, and engagement type recorded
- [ ] Engagement ID and tenant_id recorded in `docs/commercial/founder_approval_checklist.md`
- [ ] Client contact invited to portal (named-user invitation sent via console → Invitations)
- [ ] Confirm client received the portal invitation email (check spam together on a call if needed)
- [ ] Pre-engagement database backup taken (`scripts/backup/fg_backup.sh backup --type pre-engagement`)
- [ ] Backup confirmed: exit code 0, size > 1 MB, verification_status "verified"
- [ ] Pre-flight checklist from `docs/operators/first_client_prep.md` completed the day before the meeting

---

## Technical Prep — Client Side

Confirm these are complete before the session:

- [ ] Azure AD app registration complete (Global Admin or Application Admin completed the setup per `docs/operators/azure_ad_app_setup.md`)
- [ ] All 15 delegated Microsoft Graph permissions present and admin consent granted
- [ ] Authentication → Advanced settings → Allow public client flows: set to Yes
- [ ] `FG_MSAL_CLIENT_ID` in Railway updated to the Application (client) ID of the new registration
- [ ] `CORE_TENANT_ID` in portal deployment updated to this client's tenant_id — NOT `default` or `frostgate-internal`
- [ ] Technical contact designated and confirmed available for the session
- [ ] Global Administrator or Application Administrator confirmed available for the first 30 minutes of the session
- [ ] Client has reviewed the security questionnaire introduction (or will walk through it during the session)
- [ ] Session date, time, and video link confirmed in writing

---

## Data Collection Session

**Before the meeting (operator, no client required):**
- [ ] DNS and Email Security scan complete — domain(s) provided; "Scan complete" status visible in console
- [ ] Web Security Headers scan complete — public URLs provided; "Scan complete" status visible in console
- [ ] Network scan complete (if in scope) — IP/hostname list provided; "Scan complete" status visible in console
- [ ] All three passive scans show "Scan complete" before the meeting starts — do not start the meeting if any are still running

**During the meeting:**
- [ ] FrostGate console open and signed in
- [ ] Real engagement (client name, not test) is active with status "In Progress"
- [ ] Client tenant ID on clipboard or written down
- [ ] Browser tab ready at `microsoft.com/devicelogin`
- [ ] Client administrator is present and ready to authenticate
- [ ] MS Graph Core scan initiated; client enters device code and authenticates
- [ ] All MS Graph connectors run in sequence: Core, MFA, Conditional Access, Devices, SharePoint, OAuth Inventory, OAuth Risk, Entra Governance, Identity Protection
- [ ] All MS Graph connectors show "Scan complete" or recorded as "not supported" with reason
- [ ] Questionnaire walkthrough complete — all 69 controls recorded
- [ ] Any relevant policy documents uploaded (acceptable use policy, AI governance policy, etc.)
- [ ] Delivery date committed verbally to client ("You will have portal access by [DATE]")

---

## Post-Collection — Operator

After the session (before report delivery):

- [ ] Evidence reviewed and curated in console
- [ ] Any scan errors investigated and documented
- [ ] AI executive summary generation triggered (console → Reports → Generate)
- [ ] Report reviewed for accuracy, grammar, and plain-language clarity
- [ ] QA checklist items verified (findings match evidence, risk scores consistent, executive summary reflects findings)
- [ ] Report submitted for QA approval by designated reviewer (reviewer ≠ assessor — SoD enforced)
- [ ] QA approve triggered by reviewer with `governance:qa_approve` scope
- [ ] Report qualification triggered (requires all FG_RESULT_TRUTH_GATE gates attested — see `docs/commercial/production_delivery_boundary.md`)
- [ ] Governed delivery authorization triggered
- [ ] Portal access invitation accepted by client (confirm in portal session records)
- [ ] Portal URL and access code prepared
- [ ] Portal URL and access code delivered via split channel (URL and password sent separately — never plaintext in the same message)

---

## Post-Delivery

- [ ] Delivery meeting scheduled (Day 10 from data collection session)
- [ ] Delivery meeting conducted: executive summary walkthrough, top findings review, portal tour (client clicks, not operator)
- [ ] 30-day check-in call scheduled in the meeting (not by email after)
- [ ] 30-day follow-up letter sent at Day 30 (`docs/operators/letters/5_remediation_followup_30day.md`)
- [ ] 30-day re-scan of passive connectors run; delta summary delivered
- [ ] Remediation progress noted (findings marked resolved by client?)
- [ ] At Day 30+, ask for feedback interview (design partner) or CG pitch (standard)
- [ ] Engagement close-out letter sent (`docs/operators/letters/6_engagement_closeout.md`)
- [ ] Post-engagement retrospective completed within 5 days of close (see `docs/operators/FIRST_CLIENT_PLAYBOOK.md` §9)
- [ ] Second payment confirmed received (if 50/50 split)
- [ ] `ROADMAP.md` updated with engagement outcome

---

## Escalation Contacts

| Situation | Action |
|-----------|--------|
| Azure AD app registration blocked | Work through `docs/operators/azure_ad_app_setup.md` with client IT; allow 1 extra business day before escalating |
| MS Graph scan fails during meeting | Fall back per runbook; continue interviews; run scan post-meeting; never debug live more than 10 minutes |
| Portal login fails for client | Same-day fix commitment; if more than 4 hours, deliver report by encrypted email and document the incident |
| Any data integrity or tenant exposure event | Stop engagement; call client within 24 hours; founder communicates directly |
| Scope creep ("can you also assess X?") | "Great Phase 2 topic" — log it; do not deliver it; quote separately if client wants it |
