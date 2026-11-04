# Stripe Test-Mode Acceptance Runbook

**Work item:** L14-STRIPE-TEST-001  
**Gate status:** `OPERATOR_ACTION_REQUIRED`  
**Last updated:** 2026-11-03  

This runbook provides deterministic, step-by-step instructions for validating the Stripe payment-to-assessment verification flow in test mode. It does not constitute evidence of a successful payment. The result field in the evidence schema must remain `OPERATOR_ACTION_REQUIRED` until a human operator completes all external steps below.

---

## Prerequisites

- Stripe account with test-mode access (no real charges)
- Stripe CLI installed: `stripe --version` (see https://stripe.com/docs/stripe-cli)
- FrostGate API running locally or in a staging environment
- `STRIPE_API_KEY` set to a `sk_test_...` key
- `STRIPE_WEBHOOK_SECRET` set to a `whsec_test_...` value (from `stripe listen` output)
- `STRIPE_SECRET_KEY` env var also set to the same test key (used by the checkout creation route)

---

## Step 1 — Configure test-mode Stripe credentials

```bash
# OPERATOR_ACTION_REQUIRED: Set real Stripe test-mode keys.
# Obtain from https://dashboard.stripe.com/test/apikeys
export STRIPE_API_KEY="sk_test_..."        # from Stripe Dashboard, test mode
export STRIPE_SECRET_KEY="sk_test_..."     # same value — used by checkout route
export STRIPE_WEBHOOK_SECRET=""            # leave blank for now — Step 3 sets this
```

Verify the key works:

```bash
curl https://api.stripe.com/v1/balance \
  -u "${STRIPE_API_KEY}:"
# Expected: {"object":"balance",...}
```

---

## Step 2 — Create a test Checkout Session

Use the FrostGate API to create a bound Checkout Session. This records `expected_amount_cents`, `payment_purpose`, and `checkout_idempotency_key` server-side.

```bash
# OPERATOR_ACTION_REQUIRED: replace <TENANT_API_KEY> and <ASSESSMENT_ID>
#   - Create a test tenant and assessment first if needed
#   - Use a valid assessment_id from the database
curl -X POST http://localhost:8000/ingest/assessment/<ASSESSMENT_ID>/checkout \
  -H "Authorization: Bearer <TENANT_API_KEY>" \
  -H "Content-Type: application/json"
```

Expected response:
```json
{
  "checkout_url": "https://checkout.stripe.com/c/pay/cs_test_...",
  "assessment_id": "<ASSESSMENT_ID>"
}
```

Record the `cs_test_...` session ID and the `checkout_url`.

---

## Step 3 — Start the Stripe CLI webhook listener

```bash
# OPERATOR_ACTION_REQUIRED: Run in a separate terminal.
# This binds the webhook to your local server and prints whsec_test_...
stripe listen \
  --forward-to http://localhost:8000/ingest/assessment/webhooks/stripe \
  --events checkout.session.completed
```

Copy the `whsec_test_...` output and set:

```bash
export STRIPE_WEBHOOK_SECRET="whsec_test_..."
# Restart the FrostGate API process with this env var set.
```

---

## Step 4 — Trigger a test webhook event

Option A: Stripe CLI trigger (simulated, does not require a real card payment):

```bash
# OPERATOR_ACTION_REQUIRED: This requires the Stripe CLI and a live connection
# to the stripe listen process from Step 3.
stripe trigger checkout.session.completed \
  --override "checkout_session:metadata.assessment_id=<ASSESSMENT_ID>" \
  --override "checkout_session:metadata.tenant_id=<TENANT_ID>" \
  --override "checkout_session:metadata.payment_purpose=assessment_initial"
```

Option B: Complete the payment flow via browser:
1. Open the `checkout_url` from Step 2 in a browser
2. Use Stripe test card: `4242 4242 4242 4242`, any future expiry, any CVC
3. Complete the checkout flow
4. The Stripe CLI listener (Step 3) will forward the `checkout.session.completed` event to FrostGate

---

## Step 5 — Verify event reached the FrostGate handler

Check the FrostGate API logs for:

```
assessment.payment_confirmed assessment_id=<ASSESSMENT_ID>
```

Confirm the `stripe_events` table has a row:

```sql
SELECT stripe_event_id, event_type, created_at
FROM stripe_events
WHERE event_type = 'checkout.session.completed'
ORDER BY created_at DESC
LIMIT 1;
```

---

## Step 6 — Verify state transition persisted

Check the `assessments` table:

```sql
SELECT id, payment_status, stripe_session_id, expected_amount_cents, payment_purpose
FROM assessments
WHERE id = '<ASSESSMENT_ID>';
```

Expected state after success:
- `payment_status` = `'paid'`
- `stripe_session_id` = the `cs_test_...` session ID
- `expected_amount_cents` = amount set at checkout creation (e.g. `250000`)
- `payment_purpose` = `'assessment_initial'`

---

## Step 7 — Verify webhook replay is rejected

Re-trigger the same event ID using the Stripe CLI or by replaying the raw webhook body. The handler must return:

```json
{"received": true}
```

without a second state transition. The `stripe_events` table must still have exactly one row for that `stripe_event_id`.

---

## Evidence Schema

After completing Steps 1–7, fill in this evidence record:

```json
{
  "schema_version": "1.0",
  "work_item": "L14-STRIPE-TEST-001",
  "environment": "test",
  "git_sha": "<current HEAD SHA — run: git rev-parse HEAD>",
  "timestamp_utc": "<ISO 8601 — e.g. 2026-11-03T18:00:00Z>",
  "stripe_event_id_redacted": "evt_test_***",
  "checkout_session_id_redacted": "cs_test_***",
  "tenant_id": "<synthetic test tenant>",
  "assessment_id": "<synthetic test assessment>",
  "expected_amount_cents": 250000,
  "observed_amount_cents": 250000,
  "currency": "usd",
  "payment_state_before": "pending",
  "payment_state_after": "paid",
  "webhook_signature_verified": true,
  "replay_rejected": true,
  "audit_ledger_ref": "<event_id from stripe_events table>",
  "result": "OPERATOR_ACTION_REQUIRED"
}
```

**Do NOT change `result` to `PROVEN` until you have personally executed Steps 1–7 and confirmed all assertions.** The evidence file must reference a real `stripe_event_id_redacted` from a live Stripe CLI test run.

Save the completed evidence to:  
`docs/evidence/stripe_test_mode_evidence_<YYYYMMDD>.json`

---

## What a human operator must do before this gate is PROVEN

1. Obtain a Stripe account with test-mode keys (no real charges required)
2. Install the Stripe CLI and authenticate: `stripe login`
3. Run Steps 1–7 against a running FrostGate instance (local or staging)
4. Confirm all assertions in Steps 5–7
5. Fill in the evidence schema with real event IDs (redacted to last 3 chars)
6. Set `"result": "PROVEN"` only after personal confirmation
7. Commit the evidence file and reference it in the PR

**Current gate status: `OPERATOR_ACTION_REQUIRED`**  
No live Stripe test account or CLI was available during automated implementation. This runbook documents exactly what must happen. The adversarial tests in `tests/test_stripe_assessment_payment_001.py` cover all binding invariants with mocked Stripe SDK.

---

## Security notes

- Never use `sk_live_...` keys in test mode
- Never commit Stripe API keys or webhook secrets to the repository
- The `STRIPE_WEBHOOK_SECRET` must be rotated if the test listener is exposed publicly
- All evidence files must have event IDs redacted to last 3 characters
- Do not use a generic Stripe Dashboard Payment Link — it will not carry `assessment_id` metadata and will not automatically confirm payment in FrostGate's records
