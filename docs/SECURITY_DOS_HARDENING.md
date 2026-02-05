# DoS Hardening Runtime Defaults

This service enforces HTTP-layer request hardening via `DoSGuardMiddleware` and runtime server flags.

## Enforced app-level limits (env)

- `FG_DOS_GUARD_ENABLED=true`
- `FG_MAX_BODY_BYTES=1048576` (1 MB)
- `FG_MAX_QUERY_BYTES=8192`
- `FG_MAX_PATH_BYTES=2048`
- `FG_MAX_HEADERS_COUNT=100`
- `FG_MAX_HEADERS_BYTES=16384`
- `FG_MAX_HEADER_LINE_BYTES=8192`
- `FG_MULTIPART_MAX_BYTES=5242880` (5 MB)
- `FG_MULTIPART_MAX_PARTS=50`
- `FG_REQUEST_TIMEOUT_SEC=15`
- `FG_KEEPALIVE_TIMEOUT_SEC=5`
- `FG_MAX_CONCURRENT_REQUESTS=100`

In production these values must be explicitly set and positive. Startup validation fails closed when missing or invalid.

## Uvicorn runtime flags

Current container command uses:

```bash
uvicorn api.main:app \
  --host 0.0.0.0 --port 8080 \
  --timeout-keep-alive 5 \
  --timeout-graceful-shutdown 15 \
  --limit-concurrency 100 \
  --h11-max-incomplete-event-size 16384
```

## Gunicorn recommendation (if used)

If running under Gunicorn/Uvicorn workers, set:

- `--keep-alive 5`
- `--graceful-timeout 15`
- `--timeout 30`
- `--max-requests 10000`
- `--max-requests-jitter 1000`

These are documented because the repository's default runtime command is direct uvicorn.
