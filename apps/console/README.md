# FrostGate Console

## MVP2 dev startup

```bash
cd console
export CORE_API_URL="http://localhost:8000"
export CORE_API_KEY="<server-only-core-api-key>"
# server-authoritative tenant for the Console BFF
export CORE_TENANT_ID="tenant-demo"
# optional for server-side alignment artifact fetches
export CONSOLE_BASE_URL="http://localhost:3000"
npm install
npm run dev
```

Security notes:
- `CORE_API_KEY` is server-only and must never be exposed through `NEXT_PUBLIC_*`.
- BFF proxy enforces route/method allowlist and always returns `Cache-Control: no-store`.


Dependency/audit note:
- Next.js advisories should be handled in a separate dependency-only PR to avoid mixing runtime behavior changes with security patching.
