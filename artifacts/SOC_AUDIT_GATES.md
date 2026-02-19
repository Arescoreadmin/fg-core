# SOC Audit Gates — deterministic commands and Make targets

## Local verification commands
1. `make venv`
2. `python tools/ci/check_security_regression_gates.py`
3. `.venv/bin/python -m pytest -q tests/test_security_regression_gates.py`
4. `.venv/bin/python -m pytest -q tests/test_saas_features.py::TestWebhookSecurity::test_verify_signature_missing_secret_denied_by_default`
5. `.venv/bin/python -m pytest -q tests/test_saas_features.py::TestWebhookSecurity::test_verify_signature_missing_secret_unsigned_override`
6. `.venv/bin/python -m pytest -q tests/test_saas_features.py::TestSecurityAlerts::test_alert_webhook_egress_policy_blocks_private`
7. `.venv/bin/python -m pytest -q tests/test_saas_features.py::TestSecurityAlerts::test_alert_webhook_egress_policy_requires_https_in_prod`

## CI gates added/updated
- Workflow step: `.github/workflows/ci.yml`
  - `python tools/ci/check_security_regression_gates.py`
- Make target: `security-regression-gates`
  - wired into `fg-fast`.

## Required gate classes (mapped)
- **No placeholder security tests**: `check_no_placeholder_security_tests`
- **No auth middleware lies**: `check_auth_middleware_enforces`
- **No insecure override in prod/staging**: `check_no_insecure_prod_overrides` (+ existing `check_prod_unsafe_config.py`)
- **No new network egress without policy validation**: `check_network_egress_policy`
- **No missing stable error codes**: `check_stable_error_codes`

## Suggested CI snippets
- `make security-regression-gates`
- `make fg-fast`

## Enterprise additive gate IDs
- EG-CP-001: compliance control-plane extension surface exists and is tenant-scoped.
- EG-CTL-001: enterprise control catalog/crosswalk APIs and tables are present.
- EG-EXC-001: exceptions/breakglass workflows emit append-only approval logs.
- EG-GOV-001: governance risk extension supports optional SoD/quorum enforcement.
- EG-EVD-001: evidence anchor records and immutable retention flag available.
- EG-IAM-001: federation validation and group-role mapping available without removing API key auth.
- EG-AI-001: AI plane model/policy/inference/review extension surfaces are present and tenant-scoped.

- EG-PLANE-001: plane registry and plane drift checker must pass.
- EG-EVID-INDEX-001: evidence index registration/listing must be tenant-scoped and available.
- EG-RES-001: resilience smoke checks must pass degraded/overload deterministic behavior.

- EG-ART-001: artifact policy gate (`check_artifact_policy.py`) must pass.
- EG-INV-001: platform inventory gate (`make platform-inventory`) must produce deterministic outputs.
