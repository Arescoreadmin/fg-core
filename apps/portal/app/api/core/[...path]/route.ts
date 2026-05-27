import { NextRequest, NextResponse } from 'next/server';

const CORE_API_URL = (process.env.CORE_API_URL || 'http://localhost:8000').replace(/\/$/, '');
const CORE_API_KEY = process.env.CORE_API_KEY;
const CORE_TENANT_ID = process.env.CORE_TENANT_ID;
const NODE_ENV = process.env.NODE_ENV || 'development';

// Module-level in-memory rate limiter.
// For multi-node deployments replace with a Redis-backed store.
const _rlBuckets = new Map<string, { count: number; resetAt: number }>();
const RL_WINDOW_MS = Math.max(1000, parseInt(process.env.PORTAL_RL_WINDOW_MS || '60000', 10) || 60000);
const RL_MAX_REQUESTS = Math.max(1, parseInt(process.env.PORTAL_RL_MAX_REQUESTS || '60', 10) || 60);

function checkRateLimit(key: string): boolean {
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
  const m = hostname.match(/^172\.(\d{1,3})\./);
  if (m) {
    const second = Number(m[1]);
    if (second >= 16 && second <= 31) return true;
  }
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
  if (!CORE_TENANT_ID) return jsonError('CORE_TENANT_ID is not configured', 500, requestId);
  if (!isPortalPathAllowed(path, request.method)) {
    return jsonError('Route/method is not permitted by portal policy', 403, requestId);
  }

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
  headers.set('X-API-Key', CORE_API_KEY);
  headers.set('X-Tenant-ID', CORE_TENANT_ID);
  headers.set('X-Request-ID', requestId);
  headers.set('X-Portal-Source', 'client-portal');

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
  if (!checkRateLimit(`portal:${clientIp}`)) {
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
