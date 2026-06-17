import { NextRequest, NextResponse } from 'next/server';
import { COOKIE_NAME, getSessionUser, getGrantSession } from '@/lib/session';
import { getRedisClient } from '@/lib/redis';

const CORE_API_URL = (process.env.CORE_API_URL || 'http://localhost:8000').replace(/\/$/, '');
const CORE_API_KEY = process.env.CORE_API_KEY;
const CORE_TENANT_ID = process.env.CORE_TENANT_ID;
const NODE_ENV = process.env.NODE_ENV || 'development';
const DEMO_TENANT_ALLOWLIST = (process.env.FG_PORTAL_DEMO_TENANTS || process.env.PORTAL_DEMO_TENANTS || '')
  .split(',')
  .map((value) => value.trim())
  .filter((value) => /^[a-zA-Z0-9_-]{1,128}$/.test(value));

function resolvePortalTenant(sessionTenantId: string | null): string | null {
  if (sessionTenantId && DEMO_TENANT_ALLOWLIST.includes(sessionTenantId)) return sessionTenantId;
  return CORE_TENANT_ID || null;
}

function parseDemoTenantKeys(raw: string | undefined): Record<string, string> {
  if (!raw) return {};
  try {
    const parsed = JSON.parse(raw) as Record<string, unknown>;
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return {};
    return Object.fromEntries(
      Object.entries(parsed)
        .map(([tenant, key]) => [tenant.trim(), typeof key === 'string' ? key.trim() : ''])
        .filter(([tenant, key]) => DEMO_TENANT_ALLOWLIST.includes(tenant) && key.length > 0),
    );
  } catch {
    return {};
  }
}

const DEMO_TENANT_API_KEYS = parseDemoTenantKeys(
  process.env.FG_PORTAL_DEMO_TENANT_KEYS || process.env.FG_DEMO_TENANT_API_KEYS,
);

function resolveCoreApiKey(tenantId: string): string | null {
  if (tenantId === CORE_TENANT_ID) return CORE_API_KEY || null;
  return DEMO_TENANT_API_KEYS[tenantId] || null;
}

const _rlBuckets = new Map<string, { count: number; resetAt: number }>();
const RL_WINDOW_MS = Math.max(1000, parseInt(process.env.PORTAL_RL_WINDOW_MS || '60000', 10) || 60000);
const RL_MAX_REQUESTS = Math.max(1, parseInt(process.env.PORTAL_RL_MAX_REQUESTS || '60', 10) || 60);

async function checkRateLimit(key: string): Promise<boolean> {
  const redis = getRedisClient();
  if (redis) {
    try {
      const windowSec = Math.ceil(RL_WINDOW_MS / 1000);
      const count = await redis.incr(key);
      if (count === 1) await redis.expire(key, windowSec);
      return count <= RL_MAX_REQUESTS;
    } catch {
      // Redis unavailable — fall through to in-memory
    }
  }
  const now = Date.now();
  const entry = _rlBuckets.get(key);
  if (!entry || now >= entry.resetAt) {
    _rlBuckets.set(key, { count: 1, resetAt: now + RL_WINDOW_MS });
    return true;
  }
  entry.count += 1;
  return entry.count <= RL_MAX_REQUESTS;
}

// Portal proxy rules — read-only by default.
// Write paths are explicitly enumerated in PORTAL_WRITE_PATTERNS below.
const PROXY_RULES: Array<{ prefix: string; methods: ReadonlySet<string> }> = [
  { prefix: 'governance/assets', methods: new Set(['GET', 'HEAD']) },
  { prefix: 'field-assessment/engagements', methods: new Set(['GET', 'HEAD']) },
  { prefix: 'ui/ai/chat', methods: new Set(['POST']) },
  { prefix: 'portal', methods: new Set(['GET', 'HEAD']) },
];

// Explicit write paths allowed through the portal BFF.
// All POST mutations from clients are soft-gated: attestations go to
// pending_operator_review; report verify is read-only at the backend.
const PORTAL_WRITE_PATTERNS: Array<{ pattern: RegExp; methods: ReadonlySet<string> }> = [
  {
    // POST governance/assets/{assetId}/attestations — submit client attestation
    pattern: /^governance\/assets\/[^/]+\/attestations$/,
    methods: new Set(['GET', 'POST', 'HEAD']),
  },
  {
    // POST field-assessment/engagements/{id}/reports/{version}/verify
    pattern: /^field-assessment\/engagements\/[^/]+\/reports\/\d+\/verify$/,
    methods: new Set(['POST']),
  },
  {
    // PATCH field-assessment/engagements/{id}/findings/{findingId} — close-loop status update
    pattern: /^field-assessment\/engagements\/[^/]+\/findings\/[^/]+$/,
    methods: new Set(['GET', 'PATCH', 'HEAD']),
  },
];

function isPortalPathAllowed(path: string[], method: string): boolean {
  const joined = path.join('/');
  for (const { pattern, methods } of PORTAL_WRITE_PATTERNS) {
    if (pattern.test(joined)) return methods.has(method);
  }
  const rule = PROXY_RULES.find(
    (item) => joined === item.prefix || joined.startsWith(`${item.prefix}/`),
  );
  return !!rule && rule.methods.has(method);
}

function isPrivateHost(hostname: string): boolean {
  if (hostname === 'localhost' || hostname.endsWith('.localhost')) return true;
  if (/^127\./.test(hostname)) return true;
  if (hostname === '::1') return true;
  if (/^10\./.test(hostname)) return true;
  if (/^192\.168\./.test(hostname)) return true;
  if (/^169\.254\./.test(hostname)) return true;
  if (/^100\.(6[4-9]|[789]\d|1[01]\d|12[0-7])\./.test(hostname)) return true;
  const m = hostname.match(/^172\.(\d{1,3})\./);
  if (m) {
    const second = Number(m[1]);
    if (second >= 16 && second <= 31) return true;
  }
  if (/^fe[89ab][0-9a-f]:/i.test(hostname)) return true;
  if (/^f[cd][0-9a-f]{2}:/i.test(hostname)) return true;
  return false;
}

function getRequestId(request: NextRequest): string {
  return request.headers.get('x-request-id') || crypto.randomUUID();
}

function jsonError(message: string, status: number, requestId: string): NextResponse {
  return NextResponse.json(
    { detail: message, code: `HTTP_${status}`, request_id: requestId },
    { status, headers: { 'Cache-Control': 'no-store', 'x-request-id': requestId } },
  );
}

function buildCoreUrl(path: string[], request: NextRequest): string {
  const incoming = new URL(request.url);
  const query = new URLSearchParams(incoming.search);
  // Never forward client-supplied tenant_id — resolved server-side from CORE_TENANT_ID
  query.delete('tenant_id');
  const qs = query.toString();
  return `${CORE_API_URL}/${path.join('/')}${qs ? `?${qs}` : ''}`;
}

async function proxyToCore(
  request: NextRequest,
  path: string[],
  requestId: string,
): Promise<NextResponse> {
  if (!CORE_API_KEY) return jsonError('CORE_API_KEY is not configured', 500, requestId);
  if (!isPortalPathAllowed(path, request.method)) {
    return jsonError('Route/method is not permitted by portal policy', 403, requestId);
  }

  const sessionToken = request.cookies.get(COOKIE_NAME)?.value;
  const sessionUser = await getSessionUser(sessionToken);
  const grantSession = await getGrantSession(sessionToken);
  const sessionId = grantSession?.sessionId ?? null;
  const tenantId = resolvePortalTenant(grantSession?.tenantId ?? null);
  if (!tenantId) return jsonError('CORE_TENANT_ID is not configured', 500, requestId);
  const coreApiKey = resolveCoreApiKey(tenantId);
  if (!coreApiKey) return jsonError('Tenant API key is not configured', 500, requestId);

  const target = buildCoreUrl(path, request);
  try {
    const { hostname } = new URL(target);
    if (NODE_ENV !== 'development' && isPrivateHost(hostname)) {
      return jsonError('Target host is not allowed', 403, requestId);
    }
  } catch {
    return jsonError('Invalid upstream URL', 500, requestId);
  }

  const headers = new Headers();
  headers.set('X-API-Key', coreApiKey);
  headers.set('X-Tenant-ID', tenantId);
  headers.set('X-Request-ID', requestId);
  headers.set('X-Portal-Source', 'client-portal');

  if (sessionId) {
    headers.set('X-FG-Portal-Session', sessionId);
  }
  if (sessionUser) {
    headers.set('X-FG-User-ID', sessionUser.userId);
    headers.set('X-FG-User-Email', sessionUser.email);
    if (sessionUser.membershipVersion > 0) {
      headers.set('X-FG-Membership-ID', sessionUser.userId);
      headers.set('X-FG-Membership-Version', String(sessionUser.membershipVersion));
    }
  }

  const contentType = request.headers.get('content-type');
  if (
    contentType &&
    (request.method === 'POST' || request.method === 'PATCH' || request.method === 'PUT')
  ) {
    headers.set('Content-Type', contentType);
  }

  const init: RequestInit = { method: request.method, headers, cache: 'no-store' };
  if (request.method !== 'GET' && request.method !== 'HEAD') {
    init.body = await request.text();
  }

  console.info(`[portal-proxy] ${requestId} ${request.method} ${target}`);
  const response = await fetch(target, init);
  const body = await response.text();
  const out = new NextResponse(body, {
    status: response.status,
    headers: {
      'Cache-Control': 'no-store',
      'x-request-id': response.headers.get('x-request-id') || requestId,
    },
  });
  const ct = response.headers.get('content-type');
  if (ct) out.headers.set('content-type', ct);
  return out;
}

async function handle(
  request: NextRequest,
  { params }: { params: { path: string[] } },
): Promise<NextResponse> {
  const requestId = getRequestId(request);
  const path = params.path || [];
  if (!path.length) return jsonError('Missing path', 400, requestId);

  const clientIp =
    request.headers.get('x-real-ip') ||
    request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() ||
    'unknown';
  if (!(await checkRateLimit(`portal:${clientIp}`))) {
    return jsonError('Too many requests', 429, requestId);
  }

  return proxyToCore(request, path, requestId);
}

export async function GET(req: NextRequest, ctx: { params: { path: string[] } }) {
  return handle(req, ctx);
}
export async function POST(req: NextRequest, ctx: { params: { path: string[] } }) {
  return handle(req, ctx);
}
export async function HEAD(req: NextRequest, ctx: { params: { path: string[] } }) {
  return handle(req, ctx);
}
export async function PATCH(req: NextRequest, ctx: { params: { path: string[] } }) {
  return handle(req, ctx);
}
