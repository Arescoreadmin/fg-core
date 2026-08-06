# T8 Incident Drill — Rollback Under 15 Minutes

**DoD L7:** Test alert fired and acknowledged within target, and a Railway rollback to the previous deploy completed in under 15 minutes.

**Owner:** Operator (founder for Stage 1)
**Frequency:** Execute once before first client engagement; re-run after any significant infrastructure change.

---

## Pre-Drill Checklist

Before starting the clock:

- [ ] No real client engagement is active or in progress on this deployment.
- [ ] You have Railway CLI authenticated (`railway whoami` returns your account).
- [ ] You have access to Railway dashboard and logs for the `api` service.
- [ ] Note the current healthy deployment ID:

```
railway status --service api
```

Record the **current deployment ID** as `DEPLOY_BEFORE`:

```
DEPLOY_BEFORE: ______________________________________
```

- [ ] Confirm GET /health returns 200:

```
curl -s -o /dev/null -w "%{http_code}" https://api.frostgate.ai/health
```

Expected: `200`

---

## Failure Injection Options

Choose **one** of the following methods. Option A creates a more realistic drill (true startup failure). Option B is faster and avoids any code commit.

### Option A — Bad env var that causes startup failure

1. In the Railway dashboard (or CLI), set a required env var to a corrupt value on the `api` service:

```
railway variable set DATABASE_URL=postgres://invalid:invalid@nowhere:5432/fake --service api
```

2. This triggers an automatic redeploy. The new container will fail to start — Railway will show crash-loop behavior in the logs.

3. Reset the variable to the correct value **after** you have practiced the rollback (do not leave the service broken). If you need to retrieve the real value, check Railway's variable history before overwriting it.

### Option B — Deploy a known-bad commit (returns 500 on /health)

1. On a scratch branch, add a one-line change to the health endpoint that always raises an exception. Do not merge to main.
2. Deploy that branch directly to the Railway `api` service using the Railway dashboard's "Deploy Branch" option.
3. Observe the 500 responses on GET /health.
4. Rollback to the previous deployment (step below) — the known-bad branch is abandoned automatically.

**Option A is the recommended method for drills** — it does not require a code change and more accurately reflects a misconfiguration incident.

---

## Drill Procedure

### Step 1 — Inject the failure

Execute the chosen injection option above.

Record: **Injection time (T0):** `________________________________`

### Step 2 — Detect

Watch Railway logs for the `api` service. Confirm failure:

- For Option A (startup failure): logs show container crash or exit code non-zero; Railway health check shows "Unhealthy."
- For Option B (500 on /health): curl returns 500; Railway logs show exception stack trace.

```
# Confirm failure
curl -s -o /dev/null -w "%{http_code}" https://api.frostgate.ai/health
```

Expected output after injection: `500` or connection refused.

Record: **Detection time (T1):** `________________________________`
Record: **Elapsed since injection (T1 - T0):** `________________`

### Step 3 — Acknowledge

State the incident aloud or in writing (for the drill log):

> "Incident acknowledged at [T1]. GET /health returning [status]. Initiating rollback to deploy [DEPLOY_BEFORE]."

Record: **Acknowledgement time:** `________________________________`

### Step 4 — Execute rollback

In the Railway dashboard:

1. Navigate to the `api` service.
2. Click **Deployments**.
3. Find the row for `DEPLOY_BEFORE`.
4. Click **Redeploy** (or the three-dot menu → **Rollback**).

Via CLI — restore the broken variable instead (the CLI does not support targeting a
specific deployment ID; `railway redeploy` always redeploys the latest):

```
railway variable set DATABASE_URL=<correct_value> --service api
```

This triggers a new deployment with the correct variable and is faster than the
dashboard when you have the real value already saved.

Monitor the deployment log until the service shows **Healthy**.

Record: **Rollback initiated (T2):** `________________________________`
Record: **Service healthy again (T3):** `________________________________`

### Step 5 — Verify recovery

```
curl -s https://api.frostgate.ai/health | python3 -m json.tool
```

Expected: HTTP 200 with `"status": "ok"` (or equivalent healthy body).

- [ ] GET /health returns 200
- [ ] Response body shows no error state
- [ ] Railway dashboard shows deployment as "Active / Healthy"

Record the /health response body below (or paste to drill log):

```
(paste response here)
```

### Step 6 — Verify audit log continuity

Confirm the audit chain was not broken by the incident:

```
curl -s -H "X-API-Key: <operator-key>" \
  https://api.frostgate.ai/api/core/audit/chain/verify
```

Expected: `"status": "verified"` (or equivalent chain-ok response). If the chain shows a gap, escalate per `disaster_recovery.md §6`.

- [ ] Audit chain: verified

---

## Evidence Record

Fill in after the drill completes:

| Field | Value |
|---|---|
| Drill date | |
| Operator | |
| Injection method (A or B) | |
| DEPLOY_BEFORE (deployment ID) | |
| DEPLOY_AFTER (rollback target, same as DEPLOY_BEFORE) | |
| Injection time (T0) | |
| Detection time (T1) | |
| Detection elapsed (T1 - T0) | |
| Rollback initiated (T2) | |
| Service healthy (T3) | |
| **Total elapsed T1 → T3** | |
| /health HTTP status after recovery | |
| /health response body summary | |
| Audit chain status after recovery | |
| Any complications or observations | |

**Pass criteria:** Total elapsed T1 → T3 is under 15 minutes AND /health returns 200 AND audit chain is verified.

---

## Escalation

If the rollback does not restore a healthy state within 10 minutes:

1. Check Railway deployment logs for errors that persist after rollback.
2. If the DATABASE_URL was changed and the old value is lost, retrieve it from Railway's variable history or the secrets manager.
3. If the issue is not a bad env var or bad code deploy, escalate to `disaster_recovery.md §3` for full recovery procedure.
4. If more than 15 minutes has elapsed without recovery, communicate to any active stakeholders using the template in `disaster_recovery.md §7`.

---

## Cross-references

- `docs/operators/disaster_recovery.md` — full recovery procedure and escalation
- `docs/operators/production_configuration_changes.md` — env var reference
- `docs/governance/status/LAUNCH_DECISION_RECORD.md` — rollback trigger conditions
