# Stripe Sandbox Acceptance Evidence — L14-STRIPE-WEBHOOK-EVENT-CONVERSION

**Status:** OPERATOR_REPORTED — historical evidence reported by the human operator who conducted the sandbox run. This is NOT a test executed by Claude. Claude has not performed a live Stripe transaction.

**Date:** November 5, 2026  
**Work item:** L14-STRIPE-WEBHOOK-EVENT-CONVERSION (P0 hotfix)  
**Stripe SDK:** 15.3.1  
**Repository branch:** `fix/l14-stripe-webhook-event-conversion`

---

## Incident Summary

A live Stripe sandbox Checkout (`acct_1TcAztB9b33yxnOR`) exposed a production-relevant integration defect. After a successful payment, the Stripe webhook delivery returned HTTP 500 instead of 200, leaving the assessment unpaid in FrostGate despite Stripe reporting the payment as complete.

**Root cause:** `api/stripe_webhooks.py::_verify_webhook_signature()` called `dict(event)` on the object returned by `stripe.Webhook.construct_event()`. In Stripe Python SDK 15.x, `construct_event()` returns a `stripe.Event` (a `StripeObject`), whose `__iter__` is integer-indexed. Calling `dict()` on it raises `KeyError: 0`, which propagates as an HTTP 500 and prevents payment confirmation.

**Fix:** Changed `return dict(event)` to `return event.to_dict()`. The public `to_dict()` method on `StripeObject` returns a plain Python `dict` with all nested fields preserved.

---

## Sandbox Acceptance Evidence (Operator-Reported)

| Field | Value |
|---|---|
| Environment | Stripe sandbox |
| Date | November 5, 2026 |
| SDK | stripe-python 15.3.1 |
| Stripe account | acct_1TcAztB9b33yxnOR (sandbox only) |
| Assessment ID | `50d42c30-b70f-477b-a09d-54a0a17d9ef6` |
| Stripe event ID | `evt_1UYQzkB9b33yxnORDWqVaVvw` |
| Amount | 29,900 cents ($299.00 USD) |
| Stripe payment status | paid |
| Webhook HTTP response (before fix) | 500 |
| Webhook HTTP response (after fix) | 200 |
| FrostGate assessment payment status | paid |
| Durable StripeEvent rows | 1 |
| payment_confirmed_at | `2026-11-05 14:05:44.711342+00:00` |
| Database acceptance checks | 8/8 passed |
| Tenant binding | PASS |
| Amount binding | PASS (29,900 cents) |
| Payment purpose | PASS (assessment_initial) |
| Session binding | PASS |

---

## Recovery Mechanism

After applying `event.to_dict()`, the same Stripe event (`evt_1UYQzkB9b33yxnORDWqVaVvw`) was redelivered to the webhook endpoint. The idempotency guard (`payment_status == "paid"` early-return) protected the already-paid assessment from double-confirmation.

---

## What This Evidence Proves

- Stripe sandbox Checkout payment: **PROVEN** (operator-executed)
- Signed webhook processing with `to_dict()`: **PROVEN** (operator-executed)
- Durable payment confirmation: **PROVEN** (operator-executed)
- Automated SDK serialization regression: **PROVEN** (see `tests/test_stripe_sdk_regression_001.py::test_sdk_01_to_dict_returns_plain_dict`)

## What This Evidence Does Not Prove

- Production Stripe acceptance: **NOT_PROVEN**
- Production client portal handoff: **NOT_PROVEN**
- Commercial $2,500 deposit pricing: **NOT_ALIGNED** (evidence used $299.00)
- Multi-tenant production isolation at scale: **NOT_PROVEN**

---

## Security Notes

- No API keys, signing secrets, checkout URLs, or raw webhook payloads are recorded here.
- The Stripe sandbox account uses test-mode credentials only. No real funds were moved.
- The event ID is recorded as operator evidence; it is not a secret and does not expose customer data.
- The `stripe_events` table row for this event must be retained as the durable payment audit anchor.
