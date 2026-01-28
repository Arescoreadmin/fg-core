# Admin Gateway Contracts

Generated artifacts for the admin-gateway API.

## Generation

Run:

```
make contracts-gen
```

This produces:

- `contracts/admin/openapi.json` (admin-gateway OpenAPI)
- JSON Schemas derived from `contracts/admin/schemas.py`:
  - `contracts/admin/health.json`
  - `contracts/admin/version.json`
  - `contracts/admin/audit.json`

## Linting

`make fg-contract` regenerates the artifacts and fails if the committed files are stale.
