# Dashboard Platform

## Persona model

Personas are resolved from scopes in `/ui/registry/persona`:

- `admin` when `admin:read` is present
- `forensics` when `forensics:read` is present
- `controls` when `controls:read` is present
- `analyst` fallback

`/ui/registry/dashboards` filters dashboard and widget visibility by persona + widget scope requirements.

## Add a widget contract

1. Add `contracts/dashboard/widgets/<id>.json` matching `contracts/dashboard/schema/widget.schema.json`.
2. Set `data_provider` to a provider key implemented by `api/ui_dashboard_data.py`.
3. Set `permissions.scopes` and `degrade_ok` according to fail-closed expectations.
4. Run `python tools/ci/check_dashboard_contracts.py`.

## Add a dashboard view

1. Add dashboard entry to `contracts/dashboard/views.json`.
2. Ensure widgets referenced exist in `contracts/dashboard/widgets/*.json`.
3. Validate against `contracts/dashboard/schema/views.schema.json`.
4. Run `make verify-schemas`.

## Add a tenant theme

1. Add `contracts/dashboard/themes/<tenant>.json` using `contracts/dashboard/schema/theme.schema.json`.
2. Use safe `logo_url` schemes (`https`, `http`, `data`).
3. CSS overrides are sanitized and reject dangerous patterns (`@import`, `javascript:` URLs).
4. Read via `GET /ui/theme`.

## Tests and gates

- Unit/security tests cover registry, snapshot guardrails, theme isolation/sanitization, and UI regressions.
- Contract checks run in:
  - `make verify-schemas`
  - `make fg-contract`
- Contract checker script: `tools/ci/check_dashboard_contracts.py`.


## Widget runtime policy

Use `contracts/dashboard/widget_runtime_policy.json` to disable widgets per tenant/persona at runtime.
Every widget load attempt is logged with tenant/persona/widget and policy allow/deny outcome.
