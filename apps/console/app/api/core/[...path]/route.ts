import { NextRequest, NextResponse } from 'next/server';
import { getRateLimitStore, getBffRateLimitConfig } from '@/lib/rateLimitStore';

const CORE_API_URL = (process.env.CORE_API_URL || 'http://localhost:8000').replace(/\/$/, '');
const CORE_API_KEY = process.env.CORE_API_KEY;
const CORE_TENANT_ID = process.env.CORE_TENANT_ID;
const NODE_ENV = process.env.NODE_ENV || 'development';
const ALLOW_TENANT_QUERY_OVERRIDE = NODE_ENV === 'development' && process.env.FG_CONSOLE_ALLOW_TENANT_QUERY_OVERRIDE === '1';

const PROXY_RULES: Array<{ prefix: string; methods: ReadonlySet<string> }> = [
  { prefix: 'health/live', methods: new Set(['GET', 'HEAD']) },
  { prefix: 'health/ready', methods: new Set(['GET', 'HEAD']) },
  { prefix: 'stats/summary', methods: new Set(['GET', 'HEAD']) },
  { prefix: 'feed/live', methods: new Set(['GET', 'HEAD']) },
  { prefix: 'decisions', methods: new Set(['GET', 'HEAD']) },
  { prefix: 'forensics/chain/verify', methods: new Set(['GET', 'HEAD']) },
  { prefix: 'forensics/snapshot', methods: new Set(['GET', 'HEAD']) },
  { prefix: 'forensics/audit_trail', methods: new Set(['GET', 'HEAD']) },
  { prefix: 'keys', methods: new Set(['GET', 'POST', 'DELETE', 'HEAD']) },
  { prefix: 'control-tower/snapshot', methods: new Set(['GET', 'HEAD']) },
  { prefix: 'admin/connectors/status', methods: new Set(['GET', 'HEAD']) },
  { prefix: 'admin/connectors', methods: new Set(['POST', 'GET', 'HEAD']) },
  { prefix: 'admin/agent/devices', methods: new Set(['GET', 'HEAD']) },
  { prefix: 'admin/agent/quarantine', methods: new Set(['POST']) },
  { prefix: 'admin/agent/unquarantine', methods: new Set(['POST']) },
  { prefix: 'control-plane/lockers', methods: new Set(['GET', 'POST', 'HEAD']) },
  { prefix: 'audit/export', methods: new Set(['GET', 'HEAD']) },
  // Assessment + report flow: scoped-key-gated pre-tenant endpoints
  { prefix: 'ingest/assessment', methods: new Set(['GET', 'POST', 'PATCH', 'HEAD']) },
  // AI assistant chat — governed end-user surface
  { prefix: 'ui/ai/chat', methods: new Set(['POST']) },
  // Retrieval policy governance — tenant-scoped, governance:write gated
  { prefix: 'rag/retrieval-policy', methods: new Set(['GET', 'PUT', 'HEAD']) },
  // Corpus list (policy UI + corpus console) and corpus/document detail + ingestion routes
  { prefix: 'rag/corpora', methods: new Set(['GET', 'HEAD']) },
  // POST needed for retry-ingestion placeholder; GET/HEAD for document detail
  { prefix: 'rag/documents', methods: new Set(['GET', 'POST', 'HEAD']) },
  // Document ingestion UX — upload and upload list (PR 51)
  { prefix: 'rag/upload', methods: new Set(['POST']) },
  { prefix: 'rag/uploads', methods: new Set(['GET', 'HEAD']) },
  { prefix: 'ui/forensics/events', methods: new Set(['GET', 'HEAD']) },
  { prefix: 'ui/forensics/trace', methods: new Set(['GET', 'HEAD']) },
  // Provider governance console — tenant-scoped, ui:read gated (PR 53)
  { prefix: 'ui/provider/governance', methods: new Set(['GET', 'HEAD']) },
  { prefix: 'ui/provider/routing', methods: new Set(['GET', 'HEAD']) },
  { prefix: 'ui/provider/failover', methods: new Set(['GET', 'HEAD']) },
  // Retrieval evaluation foundation — tenant-scoped, ui:read gated (PR 53)
  { prefix: 'ui/evaluation/runs', methods: new Set(['GET', 'HEAD']) },
  { prefix: 'ui/evaluation/quality', methods: new Set(['GET', 'HEAD']) },
  // Readiness control-plane — tenant-scoped, control-plane:read gated (PR 91)
  // Read-only surface: no write paths exposed through the dashboard BFF.
  { prefix: 'control-plane/readiness/frameworks', methods: new Set(['GET', 'HEAD']) },
  { prefix: 'control-plane/readiness/assessments', methods: new Set(['GET', 'HEAD']) },
  { prefix: 'control-plane/readiness/domains', methods: new Set(['GET', 'HEAD']) },
  { prefix: 'control-plane/readiness/controls', methods: new Set(['GET', 'HEAD']) },
  { prefix: 'control-plane/readiness/maturity-tiers', methods: new Set(['GET', 'HEAD']) },
  // UI audit dashboard — tenant-scoped, ui:read gated (PR 92)
  // Read-only: exposes audit ledger summary, chain integrity, and status counts.
  { prefix: 'ui/audit/overview', methods: new Set(['GET', 'HEAD']) },
  { prefix: 'ui/audit/status', methods: new Set(['GET', 'HEAD']) },
  { prefix: 'ui/audit/chain-integrity', methods: new Set(['GET', 'HEAD']) },
  // Field Assessment Engagement Substrate — operator console (PR 2)
  // governance:write required for mutations; governance:read for queries.
  // tenant_id injected server-side from CORE_TENANT_ID — never from request body.
  { prefix: 'field-assessment/engagements', methods: new Set(['GET', 'POST', 'PATCH', 'HEAD']) },
  // Governance topology graph — tenant-scoped, governance:read/write gated (PR 20)
  { prefix: 'governance/graph', methods: new Set(['GET', 'POST', 'HEAD']) },
  // Governance assets — read-only blast-radius surface (PR 20)
  { prefix: 'governance/assets', methods: new Set(['GET', 'HEAD']) },
];

function getRequestId(request: NextRequest): string {
  return request.headers.get('x-request-id') || crypto.randomUUID();
}

function jsonError(message: string, status: number, requestId: string) {
  return NextResponse.json(
    { detail: message, code: `HTTP_${status}`, request_id: requestId },
    {
      status,
      headers: {
        'Cache-Control': 'no-store',
        'x-request-id': requestId,
      },
    },
  );
}

/**
 * Build the rate-limit key in the format:
 *   fg:bff:rl:{route_group}:{tenant_id}:{client_identity}
 *
 * - route_group: first path segment (e.g. "decisions", "keys")
 * - tenant_id: from CORE_TENANT_ID env (server-resolved, never from request body)
 * - client_identity: session/user from x-frostgate-user header, else IP fallback
 *
 * Keys contain no secrets — only stable identity tokens already in headers.
 */
function buildRateLimitKey(request: NextRequest, routeGroup: string): string {
  const tenantId = CORE_TENANT_ID || 'default';
  // x-frostgate-user is set by the session layer upstream (server-side only).
  // Fall back to IP — never trust body-provided user identity.
  const userOrSession =
    request.headers.get('x-frostgate-user') ||
    request.headers.get('x-real-ip') ||
    request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() ||
    'unknown';
  // Sanitize: remove characters that could cause key collision (colon is delimiter)
  const safeGroup = routeGroup.replace(/[^a-zA-Z0-9_\-]/g, '_').slice(0, 64);
  const safeTenant = tenantId.replace(/[^a-zA-Z0-9_\-]/g, '_').slice(0, 128);
  const safeUser = userOrSession.replace(/[^a-zA-Z0-9_\-.:]/g, '_').slice(0, 128);
  return `fg:bff:rl:${safeGroup}:${safeTenant}:${safeUser}`;
}

async function enforceRateLimit(request: NextRequest, requestId: string, routeGroup: string): Promise<NextResponse | null> {
  const { windowSec, maxRequests } = getBffRateLimitConfig();
  const storeResult = await getRateLimitStore();

  if (storeResult.unavailable) {
    // Redis required but unavailable in prod-like — deterministic 503, fail-closed.
    // errorCode distinguishes missing/invalid config from transient Redis failure.
    return NextResponse.json(
      { error: storeResult.errorCode, request_id: requestId },
      {
        status: 503,
        headers: { 'Cache-Control': 'no-store', 'x-request-id': requestId },
      },
    );
  }

  const key = buildRateLimitKey(request, routeGroup);
  const result = await storeResult.store.increment(key, windowSec, maxRequests);

  if (!result.allowed) {
    return jsonError('Too many requests', 429, requestId);
  }
  return null;
}

function resolveTenant(request: NextRequest): string | null {
  const queryTenant = new URL(request.url).searchParams.get('tenant_id');
  if (ALLOW_TENANT_QUERY_OVERRIDE && queryTenant) return queryTenant;
  return CORE_TENANT_ID || null;
}

function buildCoreUrl(path: string[], request: NextRequest): string {
  const incoming = new URL(request.url);
  const query = new URLSearchParams(incoming.search);
  query.delete('tenant_id');

  const tenant = resolveTenant(request);
  if (tenant) query.set('tenant_id', tenant);

  return `${CORE_API_URL}/${path.join('/')}?${query.toString()}`.replace(/\?$/, '');
}

function isAlignmentArtifact(path: string[]) {
  return path.length === 1 && path[0] === 'alignment-artifact';
}

function isProxyPathAllowed(path: string[], method: string): boolean {
  const joined = path.join('/');
  const rule = PROXY_RULES.find((item) => joined === item.prefix || joined.startsWith(`${item.prefix}/`));
  if (!rule) return false;
  return rule.methods.has(method);
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

async function proxyToCore(request: NextRequest, path: string[], requestId: string): Promise<NextResponse> {
  if (!CORE_API_KEY) return jsonError('CORE_API_KEY is not configured', 500, requestId);

  if (!isProxyPathAllowed(path, request.method)) {
    return jsonError('Route/method is not allowed by proxy policy', 403, requestId);
  }

  const headers = new Headers();
  headers.set('X-API-Key', CORE_API_KEY);
  headers.set('X-Request-ID', requestId);
  const tenant = resolveTenant(request);
  if (tenant) headers.set('X-Tenant-ID', tenant);

  const contentType = request.headers.get('content-type');
  if (contentType && (request.method === 'POST' || request.method === 'DELETE' || request.method === 'PATCH' || request.method === 'PUT')) {
    headers.set('Content-Type', contentType);
  }

  const init: RequestInit = { method: request.method, headers, cache: 'no-store' };
  if (request.method !== 'GET' && request.method !== 'HEAD') {
    // For multipart uploads, stream the raw body and forward the content-type boundary.
    // For all other mutation methods, read as text (JSON payloads).
    const isMultipart = contentType?.toLowerCase().startsWith('multipart/form-data');
    if (isMultipart && request.body) {
      init.body = request.body;
      // duplex is required for streaming request bodies in some Node.js environments
      (init as Record<string, unknown>)['duplex'] = 'half';
    } else {
      init.body = await request.text();
    }
  }

  const target = buildCoreUrl(path, request);
  console.info(`[core-proxy] ${requestId} ${request.method} ${target}`);

  const response = await fetch(target, init);
  const body = await response.text();
  const out = new NextResponse(body, {
    status: response.status,
    headers: {
      'Cache-Control': 'no-store',
      'x-request-id': response.headers.get('x-request-id') || requestId,
    },
  });
  const responseContentType = response.headers.get('content-type');
  if (responseContentType) out.headers.set('content-type', responseContentType);
  const replayHeader = response.headers.get('idempotent-replay');
  if (replayHeader) out.headers.set('idempotent-replay', replayHeader);
  const hashHeader = response.headers.get('x-response-hash');
  if (hashHeader) out.headers.set('x-response-hash', hashHeader);
  return out;
}

async function getAlignmentArtifact(requestId: string): Promise<NextResponse> {
  const artifactUrl = process.env.ALIGNMENT_ARTIFACT_URL;
  if (!artifactUrl) {
    return NextResponse.json({ artifact: null }, { headers: { 'Cache-Control': 'no-store', 'x-request-id': requestId } });
  }

  const parsed = new URL(artifactUrl);
  if (NODE_ENV !== 'development' && parsed.protocol !== 'https:') {
    return jsonError('Alignment artifact URL must use https outside development', 400, requestId);
  }

  if (isPrivateHost(parsed.hostname)) {
    return jsonError('Alignment artifact host is not allowed', 403, requestId);
  }

  const allowlist = (process.env.ALIGNMENT_ARTIFACT_HOST_ALLOWLIST || '').split(',').map((v) => v.trim()).filter(Boolean);
  if (allowlist.length === 0 && NODE_ENV !== 'development') {
    return jsonError('ALIGNMENT_ARTIFACT_HOST_ALLOWLIST must be set outside development', 500, requestId);
  }

  if (allowlist.length > 0 && !allowlist.includes(parsed.host)) {
    return jsonError('Alignment artifact host is not allowed', 403, requestId);
  }

  const response = await fetch(artifactUrl, { cache: 'no-store' });
  if (!response.ok) {
    return NextResponse.json({ artifact: null }, { headers: { 'Cache-Control': 'no-store', 'x-request-id': requestId } });
  }

  try {
    const payload = await response.json();
    return NextResponse.json({ artifact: payload }, { headers: { 'Cache-Control': 'no-store', 'x-request-id': requestId } });
  } catch {
    return jsonError('Alignment artifact payload is not valid JSON', 502, requestId);
  }
}

async function handle(request: NextRequest, { params }: { params: { path: string[] } }) {
  const requestId = getRequestId(request);
  const path = params.path || [];
  const routeGroup = path[0] || 'unknown';

  const rate = await enforceRateLimit(request, requestId, routeGroup);
  if (rate) return rate;

  if (!path.length) return jsonError('Missing path', 400, requestId);
  if (isAlignmentArtifact(path) && request.method === 'GET') return getAlignmentArtifact(requestId);
  return proxyToCore(request, path, requestId);
}

export async function GET(request: NextRequest, context: { params: { path: string[] } }) {
  return handle(request, context);
}

export async function POST(request: NextRequest, context: { params: { path: string[] } }) {
  return handle(request, context);
}

export async function PATCH(request: NextRequest, context: { params: { path: string[] } }) {
  return handle(request, context);
}


export async function PUT(request: NextRequest, context: { params: { path: string[] } }) {
  return handle(request, context);
}

export async function DELETE(request: NextRequest, context: { params: { path: string[] } }) {
  return handle(request, context);
}

export async function HEAD(request: NextRequest, context: { params: { path: string[] } }) {
  return handle(request, context);
}
