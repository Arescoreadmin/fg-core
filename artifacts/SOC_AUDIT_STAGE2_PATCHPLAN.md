# SOC Audit Stage 2 — Patch Plan (ROI-first)

## Ordered PR plan

1. **P0 webhook signature fail-closed default** ✅
   - Edit: `api/webhook_security.py`
   - Change: deny unsigned webhooks by default; allow explicit non-prod override via `FG_WEBHOOK_ALLOW_UNSIGNED=true`.
   - Regression: tests added in `tests/test_saas_features.py`.

2. **P0 alert egress policy for webhook channel** ✅
   - Edit: `api/security_alerts.py`
   - Change: add URL policy (`scheme`, hostname presence, prod HTTPS requirement, DNS resolve + private/loopback rejection).
   - Regression: tests added in `tests/test_saas_features.py`.

3. **P1 stable error code contract** ✅
   - Edit: `api/main.py`
   - Change: exception shield now emits deterministic `error_code` alongside `detail`.
   - Regression: validated indirectly by new CI gate + script.

4. **P1 consolidated regression control gate** ✅
   - Edit: `tools/ci/check_security_regression_gates.py`, `Makefile`, `.github/workflows/ci.yml`.
   - Change: central gate enforces classes:
     - no placeholder security tests,
     - auth middleware enforcement markers,
     - no insecure prod override drift,
     - network egress validation marker,
     - stable error code marker.

5. **P2 next (not patched in this PR; recommended)**
   - Add explicit egress policy validator to `api/tripwires.py` before outbound POST.
   - Tighten unmatched-route auth behavior with fail-closed default option.
   - Convert open-ended dependency ranges to fully pinned constraints.

## Exact file edits delivered for top 3 fixes
- `api/webhook_security.py`: secretless path now fail-closed except explicit unsigned override in non-prod.
- `api/security_alerts.py`: `_validate_alert_webhook_url()` added and enforced in `WebhookAlertChannel.send()`.
- `api/main.py`: `_stable_error_code()` and JSON error payload upgrade in exception shield middleware.
