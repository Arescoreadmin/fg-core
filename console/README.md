# FrostGate Console

## MVP2 dev startup

```bash
cd console
export ADMIN_GATEWAY_URL="http://localhost:8001"
# optional for server-side alignment artifact fetches
export CONSOLE_BASE_URL="http://localhost:3000"
# optional: enable tenant_id query override only in development demo sessions
export FG_CONSOLE_ALLOW_TENANT_QUERY_OVERRIDE="0"
npm install
npm run dev
```

Security notes:
- BFF authenticates human users via Admin-Gateway session cookies + CSRF tokens.
- BFF proxy enforces route/method allowlist and always returns `Cache-Control: no-store`.


Dependency/audit note:
- Next.js advisories should be handled in a separate dependency-only PR to avoid mixing runtime behavior changes with security patching.
