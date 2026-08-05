# T9 Console UX Validation

**DoD L8:** Console navigation equals the launch IA: ≤9 items, one dashboard; an operator completes an engagement end-to-end using only visible navigation.

**Operator:** ___________________________
**Date:** ___________________________
**Console URL:** console.frostgate.ai (or current Vercel deployment URL)
**Test tenant:** ___________________________

---

## Nav Item Count

Before walking through the engagement flow, open the console and count every visible sidebar item.

| # | Sidebar item label | Group |
|---|---|---|
| 1 | | |
| 2 | | |
| 3 | | |
| 4 | | |
| 5 | | |
| 6 | | |
| 7 | | |
| 8 | | |
| 9 | | |
| 10+ | (list any additional items) | |

**Total visible nav items:** _______

**≤9 items?** [ ] Yes [ ] No

If No, record which items exceed the launch IA target and note whether they should be gated (see `CONSOLE_UX_AUDIT.md §4` for the recommended launch IA).

---

## Engagement End-to-End Walkthrough

Each step uses only visible navigation — no direct URL entry, no knowledge of internal routes.

### Step 1 — Login and Dashboard

| | |
|---|---|
| **Action** | Navigate to console.frostgate.ai. Complete Auth0 OIDC login. |
| **Expected result** | Land on a single dashboard page in 1 click (no secondary navigation required to reach the home/overview state). The page title or sidebar highlights one item as "home." |
| **Pass / Fail** | [ ] Pass [ ] Fail |
| **Notes** | |

### Step 2 — Client / Tenant Management

| | |
|---|---|
| **Action** | From the dashboard, navigate to client or tenant management using a visible sidebar item. Do not type the URL directly. |
| **Expected result** | A tenant or client list page is reachable without knowing the URL. The item is visible in the sidebar. |
| **Pass / Fail** | [ ] Pass [ ] Fail |
| **Notes** | |

### Step 3 — Create or Open an Engagement

| | |
|---|---|
| **Action** | Navigate to Field Assessments (or equivalent engagement list) using the sidebar. Create a new engagement or open an existing one. |
| **Expected result** | A "New Engagement" button or equivalent is visible without scrolling. The engagement workspace opens directly after creation or selection. |
| **Pass / Fail** | [ ] Pass [ ] Fail |
| **Notes** | Engagement ID opened: |

### Step 4 — Trigger a Scan

| | |
|---|---|
| **Action** | From within the engagement workspace, locate and trigger a scan using only visible UI controls. Do not navigate to a URL directly. |
| **Expected result** | The Scans tab is visible in the workspace without scrolling past the fold or knowing the tab name in advance. At least one scan panel has a visible "Run" button. A no-auth scan (Network, DNS, or Web Headers) is initiatable without client credentials. |
| **Pass / Fail** | [ ] Pass [ ] Fail |
| **Notes** | Which scan triggered: |

### Step 5 — View Scan Results

| | |
|---|---|
| **Action** | After the scan completes (or use an engagement that already has scan results), view the scan results within the workspace. |
| **Expected result** | Scan results are listed in the Scans tab. Each result shows source type, object count, and collection date. No URL navigation required. |
| **Pass / Fail** | [ ] Pass [ ] Fail |
| **Notes** | |

### Step 6 — Generate a Report

| | |
|---|---|
| **Action** | Navigate to the Reports tab in the engagement workspace. Click the Generate button. |
| **Expected result** | The Reports tab is visible in the workspace tab bar. The Generate button is present. After generation, a report version appears in the version list. |
| **Pass / Fail** | [ ] Pass [ ] Fail |
| **Notes** | Report version generated: |

### Step 7 — QA Approval Step

| | |
|---|---|
| **Action** | Locate the QA approval action in the Reports tab or workspace. Attempt to complete the QA approval step (requires `governance:qa_approve` scope — if the logged-in account does not have this scope, record that as a note, not a failure). |
| **Expected result** | The QA Approve button is visible (not hidden behind an unknown URL) to an account with the correct scope. After approval, the report status changes. If the account lacks scope, the button is either hidden or shows a clear "insufficient permissions" state — it does not silently fail. |
| **Pass / Fail** | [ ] Pass [ ] Fail |
| **Notes** | |

---

## Invisible-Only Path Audit

List any paths that were only reachable by typing a URL directly, not through visible navigation:

| Path | Reason it matters |
|---|---|
| | |
| | |

If any core engagement flow step required direct URL entry (Steps 3–7), mark the overall assessment as Fail.

---

## Overall Assessment

| Criterion | Result |
|---|---|
| ≤9 visible nav items | [ ] Pass [ ] Fail |
| Login lands on dashboard in ≤1 click | [ ] Pass [ ] Fail |
| Engagement end-to-end completable via visible nav | [ ] Pass [ ] Fail |
| No invisible-only paths in core flow | [ ] Pass [ ] Fail |

**Overall T9 result:** [ ] **PASS** [ ] **FAIL**

If Fail, record the blocking item and the remediation action required (typically: nav registry gating per `CONSOLE_UX_AUDIT.md §4`).

**Blocking items (if any):**

---

## Cross-references

- `docs/operators/console_user_guide.md` — authoritative page reference
- `docs/governance/audits/client_launch_readiness/CONSOLE_UX_AUDIT.md` — launch IA and remediation actions
- `docs/governance/audits/client_launch_readiness/LAUNCH_DEFINITION_OF_DONE.md` — L8 DoD definition
