import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/auth';
import { canAccessConsoleRoute } from '@/lib/consoleAccess';
import { upsertTenantInRegistry, isRegistryConfigured, upsertTenantInUpstash } from '@/lib/tenant-registry';
import { internalGatewaySecret } from '@/lib/internal-gateway-secret';
import Redis from 'ioredis';

const CORE_API_URL = (process.env.CORE_API_URL || 'http://localhost:8000').replace(/\/$/, '');

const PROVISION_SCOPES = [
  'governance:read',
  'governance:write',
  'governance:qa_approve',
  'ui:read',
  'control-plane:read',
  'audit:read',
  'audit:export',
  'decisions:read',
  'feed:read',
  'ingest:write',
  'keys:read',
  'keys:write',
  'admin:read',
  'admin:write',
];

const ONE_YEAR_SECONDS = 365 * 24 * 60 * 60;
const PORTAL_KEY_PREFIX = 'portal:tenant';

// ─── Structured logging helper ────────────────────────────────────────────────
// Emits a single JSON line so operators can grep by request_id/tenant_id/stage.
// Never emits raw secrets — only presence flags, URL host, and token length.
function logEvent(
  level: 'info' | 'warn' | 'error',
  event: string,
  fields: Record<string, unknown>,
): void {
  const payload = { level, event, ts: new Date().toISOString(), ...fields };
  const line = (() => {
    try { return JSON.stringify(payload); } catch { return `[provision-tenant] ${event}`; }
  })();
  if (level === 'error') console.error(line);
  else if (level === 'warn') console.warn(line);
  else console.info(line);
}

// Return the URL host (no path, no credentials) so we can log which Upstash
// instance is being targeted without leaking the full endpoint or token.
function safeHost(rawUrl: string): string {
  try {
    return new URL(rawUrl).host;
  } catch {
    return 'invalid-url';
  }
}

function adminHeaders(): HeadersInit {
  const token = internalGatewaySecret();
  return {
    'Content-Type': 'application/json',
    'X-API-Key': token,
    'X-FG-Internal-Token': token,
    'X-Admin-Gateway-Internal': 'true',
  };
}

// ─── Persistence backend result taxonomy ──────────────────────────────────────
// Every persistence attempt returns one of these classifications. The route
// aggregates them into a top-level error code so operators can tell which
// backend was tried and why it failed WITHOUT reading server logs.
type PersistenceStatus =
  | 'ok'
  | 'not_configured'  // env vars for this backend are absent — did not attempt
  | 'unreachable'     // connection/timeout/network error
  | 'auth_failed'     // Upstash 401/403 — token mismatch
  | 'bad_response'    // Upstash returned non-OK result
  | 'threw';          // unexpected exception

interface PersistenceResult {
  status: PersistenceStatus;
  backend: 'redis' | 'upstash';
  /** Non-sensitive diagnostic message. Never contains secrets. */
  detail: string | null;
  /** Host portion of the URL used, when applicable. */
  host?: string;
}

async function writeKeyToUpstash(
  tenantId: string,
  apiKey: string,
  requestId: string,
): Promise<PersistenceResult> {
  const urlEnvName = process.env.BFF_UPSTASH_REDIS_REST_URL ? 'BFF_UPSTASH_REDIS_REST_URL' : 'UPSTASH_REDIS_REST_URL';
  const tokenEnvName = process.env.BFF_UPSTASH_REDIS_REST_TOKEN ? 'BFF_UPSTASH_REDIS_REST_TOKEN' : 'UPSTASH_REDIS_REST_TOKEN';
  const url = (process.env.BFF_UPSTASH_REDIS_REST_URL || process.env.UPSTASH_REDIS_REST_URL || '').trim();
  const token = (process.env.BFF_UPSTASH_REDIS_REST_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN || '').trim();
  if (!url || !token) {
    logEvent('warn', 'persistence.upstash.not_configured', {
      request_id: requestId, tenant_id: tenantId, has_url: !!url, has_token: !!token,
    });
    return { status: 'not_configured', backend: 'upstash', detail: 'UPSTASH_REDIS_REST_URL or UPSTASH_REDIS_REST_TOKEN not set' };
  }
  const host = safeHost(url);
  try {
    const res = await fetch(url, {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify(['SET', `${PORTAL_KEY_PREFIX}:${tenantId}:key`, apiKey, 'EX', ONE_YEAR_SECONDS]),
    });
    if (res.status === 401 || res.status === 403) {
      logEvent('error', 'persistence.upstash.auth_failed', {
        request_id: requestId, tenant_id: tenantId, host, status: res.status,
        token_env: tokenEnvName, url_env: urlEnvName, token_len: token.length,
      });
      return { status: 'auth_failed', backend: 'upstash', detail: `Upstash rejected token (HTTP ${res.status}); rotate ${tokenEnvName} in Vercel and redeploy`, host };
    }
    if (!res.ok) {
      // Read body defensively; do not include token or key material in log.
      const bodySnippet = await res.text().then(t => t.slice(0, 200)).catch(() => '');
      logEvent('error', 'persistence.upstash.bad_response', {
        request_id: requestId, tenant_id: tenantId, host, status: res.status, body_snippet: bodySnippet,
      });
      return { status: 'bad_response', backend: 'upstash', detail: `Upstash HTTP ${res.status}`, host };
    }
    const data = await res.json() as { result?: string; error?: string };
    if (data.error) {
      logEvent('error', 'persistence.upstash.command_error', {
        request_id: requestId, tenant_id: tenantId, host, error: data.error,
      });
      return { status: 'bad_response', backend: 'upstash', detail: `Upstash error: ${data.error}`, host };
    }
    if (data.result !== 'OK') {
      logEvent('error', 'persistence.upstash.unexpected_result', {
        request_id: requestId, tenant_id: tenantId, host, result: data.result ?? 'null',
      });
      return { status: 'bad_response', backend: 'upstash', detail: `Upstash returned ${data.result ?? 'null'} (expected OK)`, host };
    }
    logEvent('info', 'persistence.upstash.ok', { request_id: requestId, tenant_id: tenantId, host });
    return { status: 'ok', backend: 'upstash', detail: null, host };
  } catch (e) {
    const msg = e instanceof Error ? e.message : 'unknown error';
    logEvent('error', 'persistence.upstash.threw', {
      request_id: requestId, tenant_id: tenantId, host, error_class: e instanceof Error ? e.constructor.name : 'unknown', error: msg,
    });
    return { status: 'threw', backend: 'upstash', detail: `Upstash write threw: ${msg}`, host };
  }
}

async function revokeKey(credentialId: string, tenantId: string, requestId: string): Promise<void> {
  try {
    const res = await fetch(
      `${CORE_API_URL}/admin/tenants/${encodeURIComponent(tenantId)}/credentials/${encodeURIComponent(credentialId)}/revoke`,
      {
        method: 'POST',
        headers: adminHeaders(),
        body: JSON.stringify({ reason: 'provision-tenant: persistence failure rollback' }),
        cache: 'no-store',
      },
    );
    if (!res.ok) {
      logEvent('error', 'rollback.revoke.non_ok', {
        request_id: requestId, tenant_id: tenantId, credential_id: credentialId, status: res.status,
      });
    } else {
      logEvent('info', 'rollback.revoke.ok', {
        request_id: requestId, tenant_id: tenantId, credential_id: credentialId,
      });
    }
  } catch (e) {
    logEvent('error', 'rollback.revoke.threw', {
      request_id: requestId, tenant_id: tenantId, credential_id: credentialId,
      error: e instanceof Error ? e.message : 'unknown',
    });
  }
}

async function writeKeyToRedis(
  tenantId: string,
  apiKey: string,
  requestId: string,
): Promise<PersistenceResult> {
  const url = (process.env.BFF_REDIS_URL || process.env.REDIS_URL || '').trim();
  if (!url) {
    return { status: 'not_configured', backend: 'redis', detail: 'REDIS_URL not set' };
  }
  const host = safeHost(url);
  let client: Redis | null = null;
  try {
    client = new Redis(url, {
      maxRetriesPerRequest: 1,
      connectTimeout: 2000,
      enableOfflineQueue: false,
      lazyConnect: true,
    });
    await client.connect();
    await client.set(`${PORTAL_KEY_PREFIX}:${tenantId}:key`, apiKey, 'EX', ONE_YEAR_SECONDS);
    logEvent('info', 'persistence.redis.ok', { request_id: requestId, tenant_id: tenantId, host });
    return { status: 'ok', backend: 'redis', detail: null, host };
  } catch (e) {
    const msg = e instanceof Error ? e.message : 'unknown error';
    logEvent('error', 'persistence.redis.threw', {
      request_id: requestId, tenant_id: tenantId, host, error_class: e instanceof Error ? e.constructor.name : 'unknown', error: msg,
    });
    return { status: 'unreachable', backend: 'redis', detail: `Redis write failed: ${msg}`, host };
  } finally {
    try { client?.disconnect(); } catch { /* ignore */ }
  }
}

// Aggregate the two backend results into a single error code that operators
// can act on WITHOUT tailing server logs.
function classifyPersistenceFailure(
  redis: PersistenceResult,
  upstash: PersistenceResult,
): { code: string; detail: string } {
  // Both backends unconfigured — this is the "no persistence at all" case.
  if (redis.status === 'not_configured' && upstash.status === 'not_configured') {
    return {
      code: 'PERSISTENCE_NOT_CONFIGURED',
      detail: 'No portal persistence backend is configured. Set REDIS_URL or UPSTASH_REDIS_REST_URL + UPSTASH_REDIS_REST_TOKEN in Vercel.',
    };
  }
  // Both backends configured but both failed — surface both diagnostics.
  if (redis.status !== 'ok' && redis.status !== 'not_configured'
      && upstash.status !== 'ok' && upstash.status !== 'not_configured') {
    return {
      code: 'BOTH_PERSISTENCE_UNAVAILABLE',
      detail: `Redis: ${redis.detail ?? redis.status}. Upstash: ${upstash.detail ?? upstash.status}.`,
    };
  }
  // Only Upstash was tried (Redis unconfigured) and it failed with a specific class.
  if (redis.status === 'not_configured' && upstash.status !== 'ok') {
    if (upstash.status === 'auth_failed') {
      return {
        code: 'UPSTASH_AUTH_FAILED',
        detail: upstash.detail ?? 'Upstash rejected the configured token. Rotate UPSTASH_REDIS_REST_TOKEN (or BFF_UPSTASH_REDIS_REST_TOKEN if set) in Vercel and redeploy.',
      };
    }
    return {
      code: 'UPSTASH_UNAVAILABLE',
      detail: upstash.detail ?? 'Upstash REST write failed.',
    };
  }
  // Only Redis was tried (Upstash unconfigured) and it failed.
  if (upstash.status === 'not_configured' && redis.status !== 'ok') {
    return {
      code: 'REDIS_UNAVAILABLE',
      detail: redis.detail ?? 'Redis write failed.',
    };
  }
  // Fallback — should not be reachable when at least one is ok.
  return {
    code: 'PERSISTENCE_UNAVAILABLE',
    detail: `Redis: ${redis.detail ?? redis.status}. Upstash: ${upstash.detail ?? upstash.status}.`,
  };
}

export async function POST(req: NextRequest): Promise<NextResponse> {
  const requestId = req.headers.get('x-request-id') || crypto.randomUUID();

  const session = await auth();
  if (!session?.user) {
    return NextResponse.json({ error: 'Unauthorized', request_id: requestId }, { status: 401, headers: { 'x-request-id': requestId } });
  }
  if (!canAccessConsoleRoute('/admin/tenants', session)) {
    return NextResponse.json({ error: 'Forbidden', request_id: requestId }, { status: 403, headers: { 'x-request-id': requestId } });
  }

  if (!internalGatewaySecret()) {
    logEvent('error', 'gateway.secret.missing', { request_id: requestId });
    return NextResponse.json(
      {
        error: 'INTERNAL_GATEWAY_UNCONFIGURED',
        detail: 'Tenant provisioning is not configured. Set FG_INTERNAL_GATEWAY_SECRET (or the legacy alias FG_ADMIN_GATEWAY_TOKEN / FG_INTERNAL_AUTH_SECRET / FG_INTERNAL_TOKEN) in Vercel.',
        request_id: requestId,
      },
      { status: 503, headers: { 'x-request-id': requestId } },
    );
  }
  let body: { tenant_id?: string; name?: string };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: 'Invalid request body.', request_id: requestId }, { status: 400, headers: { 'x-request-id': requestId } });
  }

  const tenantId = (body.tenant_id ?? '').trim().toLowerCase().replace(/\s+/g, '-');
  const name = (body.name ?? tenantId).trim();

  if (!/^[a-zA-Z0-9_-]{2,128}$/.test(tenantId)) {
    return NextResponse.json(
      { error: 'tenant_id must be 2–128 characters: letters, numbers, hyphens, underscores only.', request_id: requestId },
      { status: 422, headers: { 'x-request-id': requestId } },
    );
  }

  logEvent('info', 'provision.start', { request_id: requestId, tenant_id: tenantId, stage: 'begin' });

  // Step 1: Create tenant record (skip 409 — tenant already exists, just regenerate key)
  const tenantRes = await fetch(`${CORE_API_URL}/admin/tenants`, {
    method: 'POST',
    headers: adminHeaders(),
    body: JSON.stringify({ tenant_id: tenantId, name }),
    cache: 'no-store',
  });

  const tenantAlreadyExisted = tenantRes.status === 409;

  if (!tenantRes.ok && !tenantAlreadyExisted) {
    const err = await tenantRes.json().catch(() => ({}));
    logEvent('error', 'provision.tenant.create_failed', {
      request_id: requestId, tenant_id: tenantId, status: tenantRes.status,
    });
    return NextResponse.json(
      { error: `Failed to create tenant: ${err?.detail ?? `HTTP ${tenantRes.status}`}`, request_id: requestId },
      { status: tenantRes.status, headers: { 'x-request-id': requestId } },
    );
  }

  logEvent('info', 'provision.tenant.ok', {
    request_id: requestId, tenant_id: tenantId, already_existed: tenantAlreadyExisted, stage: 'tenant_created',
  });

  // Step 2: Create BFF credential scoped to the tenant (R4.8: /admin/keys retired).
  // On slot conflict (409) the tenant was partially provisioned before — rotate instead.
  const keyRes = await fetch(
    `${CORE_API_URL}/admin/tenants/${encodeURIComponent(tenantId)}/credentials`,
    {
      method: 'POST',
      headers: adminHeaders(),
      body: JSON.stringify({
        credential_slot: 'console-bff-key',
        scopes: PROVISION_SCOPES,
        expires_in_seconds: ONE_YEAR_SECONDS,
      }),
      cache: 'no-store',
    },
  );

  let keyData: Record<string, unknown>;
  let wasRotated = false;

  if (keyRes.status === 409) {
    // Slot already occupied — the tenant was partially provisioned before. Rotate.
    // A slot conflict implies the tenant definitively existed before this request.
    wasRotated = true;

    // Query ALL statuses: a revoked credential leaves current_generation > 0 in
    // credential_slots, so the slot shows as occupied even though it cannot be rotated.
    const listRes = await fetch(
      `${CORE_API_URL}/admin/tenants/${encodeURIComponent(tenantId)}/credentials?limit=50`,
      { method: 'GET', headers: adminHeaders(), cache: 'no-store' },
    );
    if (!listRes.ok) {
      const err = await listRes.json().catch(() => ({}));
      return NextResponse.json(
        { error: `Key generation failed (slot conflict, list failed): ${err?.detail ?? listRes.status}`, request_id: requestId },
        { status: 500, headers: { 'x-request-id': requestId } },
      );
    }
    const list = await listRes.json() as { credentials?: Array<{ credential_id: string; credential_slot: string; status: string }> };
    const existing = (list.credentials ?? []).find(c => c.credential_slot === 'console-bff-key');

    if (!existing) {
      return NextResponse.json(
        { error: 'Key generation failed: slot conflict but no console-bff-key credential found. Manual DB intervention may be required.', request_id: requestId },
        { status: 500, headers: { 'x-request-id': requestId } },
      );
    }

    // Stuck-slot: the credential exists but is in a terminal state (revoked/expired/rotated)
    // so rotate_credential will reject it. The credential_slots row still shows generation > 0.
    // This requires direct DB remediation — the API cannot recover from this state.
    if (existing.status !== 'active') {
      return NextResponse.json(
        {
          error: 'SLOT_STUCK',
          detail:
            `The console-bff-key slot for tenant '${tenantId}' has a ${existing.status} credential ` +
            `(${existing.credential_id}) that cannot be rotated. ` +
            'Run the following SQL against the Postgres DB to clear it, then reprovision:\n' +
            `DELETE FROM tenant_credentials WHERE tenant_id = '${tenantId}' AND credential_slot = 'console-bff-key';\n` +
            `UPDATE credential_slots SET current_generation = 0 WHERE tenant_id = '${tenantId}' AND credential_slot = 'console-bff-key';`,
          request_id: requestId,
        },
        { status: 409, headers: { 'x-request-id': requestId } },
      );
    }

    const rotateRes = await fetch(
      `${CORE_API_URL}/admin/tenants/${encodeURIComponent(tenantId)}/credentials/${encodeURIComponent(existing.credential_id)}/rotate`,
      {
        method: 'POST',
        headers: adminHeaders(),
        body: JSON.stringify({ expires_in_seconds: ONE_YEAR_SECONDS }),
        cache: 'no-store',
      },
    );
    if (!rotateRes.ok) {
      const err = await rotateRes.json().catch(() => ({}));
      return NextResponse.json(
        { error: `Key generation failed (rotate): ${err?.detail ?? rotateRes.status}`, request_id: requestId },
        { status: 500, headers: { 'x-request-id': requestId } },
      );
    }
    keyData = await rotateRes.json();
  } else if (!keyRes.ok) {
    const err = await keyRes.json().catch(() => ({}));
    return NextResponse.json(
      { error: `Key generation failed: ${err?.detail ?? keyRes.status}`, request_id: requestId },
      { status: 500, headers: { 'x-request-id': requestId } },
    );
  } else {
    keyData = await keyRes.json();
  }

  logEvent('info', 'provision.credential.ok', {
    request_id: requestId, tenant_id: tenantId, credential_id: keyData.credential_id,
    was_rotated: wasRotated, stage: 'credential_issued',
  });

  // A slot conflict means the tenant existed regardless of what Step 1 returned.
  const alreadyExisted = tenantAlreadyExisted || wasRotated;

  const rawKey: string = keyData.plaintext_secret as string;

  // Step 3a: Write display metadata to Edge Config (does NOT store the auth key).
  // Fire-and-forget — Edge Config is for the client list UI, not portal authentication.
  if (isRegistryConfigured()) {
    upsertTenantInRegistry(tenantId, {
      label: name,
      created_at: new Date().toISOString(),
    }).catch(() => {});
  }

  // Step 3b: Write the portal auth key (portal:tenant:{id}:key) so the portal can
  // authenticate on behalf of this tenant. Always runs — independent of Edge Config.
  // Priority: ioredis (REDIS_URL) → Upstash REST (UPSTASH_REDIS_REST_URL)
  let redisResult: PersistenceResult = { status: 'not_configured', backend: 'redis', detail: 'not attempted' };
  let upstashResult: PersistenceResult = { status: 'not_configured', backend: 'upstash', detail: 'not attempted' };

  redisResult = await writeKeyToRedis(tenantId, rawKey, requestId);
  const registryLive = redisResult.status === 'ok'
    ? true
    : (upstashResult = await writeKeyToUpstash(tenantId, rawKey, requestId)).status === 'ok';

  // Fail closed: both persistence paths failed (or neither is configured).
  if (!registryLive) {
    const isProduction = (process.env.FG_ENV ?? '').trim().toLowerCase() === 'production';
    const devOverride =
      !isProduction &&
      (process.env.FG_ALLOW_UNPERSISTED_TENANT_KEYS ?? '').trim().toLowerCase() === 'true';

    if (isProduction && (process.env.FG_ALLOW_UNPERSISTED_TENANT_KEYS ?? '') !== '') {
      // Hard block: override flag must never be honoured in production.
      logEvent('error', 'security.override.ignored_in_production', {
        request_id: requestId, tenant_id: tenantId, override: 'FG_ALLOW_UNPERSISTED_TENANT_KEYS',
      });
    }

    const { code, detail } = classifyPersistenceFailure(redisResult, upstashResult);

    if (!devOverride) {
      if (wasRotated) {
        // The predecessor credential is already superseded — revoking the new one
        // would leave the tenant with zero usable credentials. Do not revoke.
        // The new credential exists live in Postgres but has no portal route to it.
        // Operator must configure persistence and manually reprovision.
        logEvent('error', 'provision.persistence.failed.rotate', {
          request_id: requestId, tenant_id: tenantId, credential_id: keyData.credential_id,
          error_code: code, rollback_performed: false,
          redis_status: redisResult.status, upstash_status: upstashResult.status,
        });
        return NextResponse.json(
          {
            error: code,
            detail:
              `Credential rotated (${keyData.credential_id as string}) but could not be persisted. ` +
              'The new credential is live in Postgres but unreachable by the portal. ' +
              `Reason: ${detail} ` +
              'Configure persistence, then reprovision to rotate again.',
            request_id: requestId,
          },
          { status: 503, headers: { 'x-request-id': requestId } },
        );
      }

      // Fresh create: revoke the dangling credential so Postgres does not accumulate
      // unreachable credentials. R7 will make Postgres the rebuild source.
      logEvent('error', 'provision.persistence.failed.fresh', {
        request_id: requestId, tenant_id: tenantId, credential_id: keyData.credential_id,
        error_code: code, rollback_performed: true,
        redis_status: redisResult.status, upstash_status: upstashResult.status,
      });
      await revokeKey(keyData.credential_id as string, tenantId, requestId);
      return NextResponse.json(
        {
          error: code,
          detail,
          request_id: requestId,
        },
        { status: 503, headers: { 'x-request-id': requestId } },
      );
    }

    // Dev/staging explicit override: return the one-time secret so the operator can
    // wire it manually. Only reachable when FG_ALLOW_UNPERSISTED_TENANT_KEYS=true
    // AND FG_ENV != production.
    logEvent('warn', 'provision.persistence.dev_override', {
      request_id: requestId, tenant_id: tenantId, error_code: code,
    });
    return NextResponse.json({
      tenant_id: tenantId,
      name,
      already_existed: alreadyExisted,
      registry_live: false,
      credential_id: keyData.credential_id,
      api_key_expires_at: keyData.expires_at,
      api_key: keyData.plaintext_secret,
      warning: `Credential was NOT persisted (${code}). ${detail}`,
      request_id: requestId,
    }, { headers: { 'x-request-id': requestId } });
  }

  // Always write full tenant record to Upstash console registry so the client
  // list persists across sessions even without Edge Config.
  await upsertTenantInUpstash(tenantId, {
    label: name,
    created_at: new Date().toISOString(),
  }).catch(() => {});

  logEvent('info', 'provision.ok', {
    request_id: requestId, tenant_id: tenantId, credential_id: keyData.credential_id,
    already_existed: alreadyExisted, backend_used: redisResult.status === 'ok' ? 'redis' : 'upstash',
    stage: 'complete',
  });

  return NextResponse.json({
    tenant_id: tenantId,
    name,
    already_existed: alreadyExisted,
    registry_live: true,
    credential_id: keyData.credential_id,
    api_key_expires_at: keyData.expires_at,
    request_id: requestId,
  }, { headers: { 'x-request-id': requestId } });
}
