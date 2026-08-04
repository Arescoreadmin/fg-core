# T10 Portal UX Validation

**DoD L9:** Every visible portal page renders real data (no permanent empty states); the dashboard leads with concrete discoveries before charts; every screen state presents one obvious next action.

**Operator:** ___________________________
**Date:** ___________________________
**Portal URL:** (current Vercel portal deployment URL)
**Test engagement:** `2a8be91cff9a43568ee8ba64c86a9ac1` (gold path engagement, if visible to the test credential)
**Test tenant:** `fg-gold-path-20260804-009`

If the gold path engagement data is not accessible via the test credential, use the most recently completed engagement that has scan results, findings, a QA-approved report, and at least one open remediation item.

---

## Pre-Validation Checklist

- [ ] You have a portal credential (named-user token or client OIDC account) for the test engagement.
- [ ] The test engagement has: scan results, findings, a QA-approved report version, and at least one open remediation item.
- [ ] You are using an incognito/private browser window with no prior portal session.
- [ ] Portal URL is reachable (HTTP 200 on the root).

---

## Step 1 — Portal Login

| | |
|---|---|
| **Action** | Open the portal URL in a private browser window. Use the named-user credential (OIDC invitation accept flow) or the token provided. Complete the Auth0 login flow. |
| **Expected result** | Login completes without intervention. User lands on the portal dashboard or engagement selector. No 401, 403, or blank screen. |
| **Pass / Fail** | [ ] Pass [ ] Fail |
| **Notes** | |

**Login method used:** [ ] Named-user OIDC (invite flow) [ ] Direct token

---

## Step 2 — Dashboard: Discoveries Before Charts

| | |
|---|---|
| **Action** | Observe the dashboard immediately after landing. Do not scroll yet. Note what appears in the visible viewport. |
| **Expected result** | The hero section leads with **concrete, named discoveries** specific to the engagement — for example: "We found 4 AI tools with access to your files" or "2 sharing links are open to anyone." These appear before or instead of abstract charts (severity counts, coverage bars). The Immediate Actions card (or equivalent) is visible. |
| **Findings-first?** | [ ] Yes, named discoveries appear before charts [ ] No, charts or abstract scores appear first |
| **Pass / Fail** | [ ] Pass [ ] Fail |
| **Notes** | Describe what appears in the viewport on load: |

---

## Step 3 — Findings Page: Real Data or Empty State

| | |
|---|---|
| **Action** | Navigate to the Findings page using visible portal navigation. |
| **Expected result** | The findings list shows real findings from the test engagement. There is no permanent empty state ("No findings" when findings exist). Each finding shows severity, title, and a plain-language description. A severity filter or sort control is visible. |
| **Pass / Fail** | [ ] Pass [ ] Fail |
| **Findings shown:** | [ ] Yes, real data [ ] Empty state (FAIL if engagement has findings) |
| **Notes** | Number of findings shown: |

### Obvious next action check

After viewing the findings list, is there exactly one obvious next action presented to the client?

- [ ] Yes — describe it: ___________________________
- [ ] No — multiple competing actions or no action presented

---

## Step 4 — Evidence View

| | |
|---|---|
| **Action** | Navigate to any evidence-linked finding or evidence view (attestation, coverage, or equivalent). |
| **Expected result** | Evidence items are populated with real data from the engagement. No "no evidence" or "coming soon" states for items that have evidence. |
| **Pass / Fail** | [ ] Pass [ ] Fail |
| **Notes** | Page navigated to: |

---

## Step 5 — Report View and Download

| | |
|---|---|
| **Action** | Navigate to the Reports page using visible navigation. Open the most recent report version. Attempt to download the PDF. |
| **Expected result** | At least one report version is listed. The report viewer renders real content (findings, executive summary, remediation plan) — no placeholder text. A "Download PDF" or "Export" button is visible and functional. The PDF, when downloaded, has the manifest hash footer and no "[PLACEHOLDER]" text. |
| **Pass / Fail** | [ ] Pass [ ] Fail |
| **Report version visible:** | [ ] Yes [ ] No |
| **PDF downloadable:** | [ ] Yes [ ] No |
| **PDF content quality:** | [ ] Real data [ ] Placeholder text detected |
| **Manifest hash in PDF footer:** | [ ] Yes [ ] No |
| **Notes** | |

---

## Step 6 — Remediation: Obvious Next Action

| | |
|---|---|
| **Action** | Navigate to Remediation (or the Immediate Actions callout on the dashboard). Open one remediation item. |
| **Expected result** | The remediation view shows open items with plain-language descriptions. Each item presents one obvious next action (e.g., "Mark as resolved" with an evidence notes field). The flow does not require knowing a URL or finding a hidden button. |
| **Pass / Fail** | [ ] Pass [ ] Fail |
| **Notes** | |

---

## Step 7 — Logout and Session Revocation

| | |
|---|---|
| **Action** | Locate the logout or sign-out control in the portal (sidebar, top-right, or equivalent). Click it. After logout, attempt to access a portal page directly via URL. |
| **Expected result** | The logout action is visible without navigating to a specific URL. After logout, direct URL access to any portal page redirects to the login screen (server-side session revoked — the session token is no longer valid, not just cleared from the browser). |
| **Logout control visible:** | [ ] Yes [ ] No — had to navigate to a specific URL |
| **Post-logout redirect works:** | [ ] Yes [ ] No (page still loads) |
| **Pass / Fail** | [ ] Pass [ ] Fail |
| **Notes** | |

---

## Stub Page Audit

Visit every page listed in the portal navigation. Record any page that renders a permanent empty state when the test engagement has data that should populate it.

| Page | Data state | Stub? |
|---|---|---|
| Dashboard | | [ ] Yes [ ] No |
| Findings | | [ ] Yes [ ] No |
| Reports | | [ ] Yes [ ] No |
| Remediation | | [ ] Yes [ ] No |
| Changes (if visible) | | [ ] Yes [ ] No |
| Export (if visible) | | [ ] Yes [ ] No |
| Other: | | [ ] Yes [ ] No |

Any page marked Stub is a failure item. Hidden stub pages (per `PORTAL_UX_AUDIT.md §4` — Changes, Export, Timeline, Trust, Continuity, Notifications, Actions) should not appear in navigation for a launch deployment.

---

## Overall Assessment

| Criterion | Result |
|---|---|
| Login completes without intervention | [ ] Pass [ ] Fail |
| Dashboard leads with named discoveries, not charts | [ ] Pass [ ] Fail |
| Findings page shows real data | [ ] Pass [ ] Fail |
| Evidence view populated | [ ] Pass [ ] Fail |
| Report view and PDF download work | [ ] Pass [ ] Fail |
| Remediation presents one obvious next action | [ ] Pass [ ] Fail |
| Logout revokes session server-side | [ ] Pass [ ] Fail |
| No permanent empty states on visible pages | [ ] Pass [ ] Fail |

**Overall T10 result:** [ ] **PASS** [ ] **FAIL**

**Blocking items (if any):**

---

## Cross-references

- `docs/governance/audits/client_launch_readiness/PORTAL_UX_AUDIT.md` — full portal audit and IA recommendations
- `docs/governance/audits/client_launch_readiness/LAUNCH_DEFINITION_OF_DONE.md` — L9 DoD definition
- `docs/operators/FIRST_CLIENT_PLAYBOOK.md` — portal access delivery procedure
