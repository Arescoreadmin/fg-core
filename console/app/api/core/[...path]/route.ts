import { NextRequest, NextResponse } from 'next/server';

const CORE_API_URL = (process.env.CORE_API_URL || 'http://localhost:8000').replace(/\/$/, '');
const CORE_API_KEY = process.env.CORE_API_KEY;
const CORE_TENANT_ID = process.env.CORE_TENANT_ID;
const NODE_ENV = process.env.NODE_ENV || 'development';

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
];

const WINDOW_MS = 10_000;
const MAX_REQUESTS_PER_WINDOW = 120;
const rateStore = new Map<string, { count: number; windowStart: number }>();

function jsonError(message: string, status: number) {
  return NextResponse.json(
    { detail: message },
    {
      status,
      headers: {
        'Cache-Control': 'no-store',
      },
    },
  );
}

function enforceRateLimit(request: NextRequest): NextResponse | null {
  const key = request.headers.get('x-real-ip') || request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() || 'unknown';
  const now = Date.now();
  const current = rateStore.get(key);

  if (!current || now - current.windowStart > WINDOW_MS) {
    rateStore.set(key, { count: 1, windowStart: now });
    return null;
  }

  current.count += 1;
  if (current.count > MAX_REQUESTS_PER_WINDOW) {
    return jsonError('Too many requests', 429);
  }
  return null;
}

function buildCoreUrl(path: string[], request: NextRequest): string {
  const incoming = new URL(request.url);
  const query = new URLSearchParams(incoming.search);

  if (query.has('tenant_id')) query.delete('tenant_id');
  if (CORE_TENANT_ID) query.set('tenant_id', CORE_TENANT_ID);

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

async function proxyToCore(request: NextRequest, path: string[]): Promise<NextResponse> {
  if (!CORE_API_KEY) return jsonError('CORE_API_KEY is not configured', 500);

  if (!isProxyPathAllowed(path, request.method)) {
    return jsonError('Route/method is not allowed by proxy policy', 403);
  }

  const headers = new Headers();
  headers.set('X-API-Key', CORE_API_KEY);
  if (CORE_TENANT_ID) headers.set('X-Tenant-ID', CORE_TENANT_ID);

  const contentType = request.headers.get('content-type');
  if (contentType && (request.method === 'POST' || request.method === 'DELETE')) {
    headers.set('Content-Type', contentType);
  }

  const init: RequestInit = { method: request.method, headers };
  if (request.method !== 'GET' && request.method !== 'HEAD') init.body = await request.text();

  const response = await fetch(buildCoreUrl(path, request), init);
  const body = await response.text();
  const out = new NextResponse(body, {
    status: response.status,
    headers: {
      'Cache-Control': 'no-store',
    },
  });
  const responseContentType = response.headers.get('content-type');
  if (responseContentType) out.headers.set('content-type', responseContentType);
  return out;
}

async function getAlignmentArtifact(): Promise<NextResponse> {
  const artifactUrl = process.env.ALIGNMENT_ARTIFACT_URL;
  if (!artifactUrl) return NextResponse.json({ artifact: null }, { headers: { 'Cache-Control': 'no-store' } });

  const parsed = new URL(artifactUrl);
  if (NODE_ENV !== 'development' && parsed.protocol !== 'https:') {
    return jsonError('Alignment artifact URL must use https outside development', 400);
  }

  if (isPrivateHost(parsed.hostname)) {
    return jsonError('Alignment artifact host is not allowed', 403);
  }

  const allowlist = (process.env.ALIGNMENT_ARTIFACT_HOST_ALLOWLIST || '').split(',').map((v) => v.trim()).filter(Boolean);
  if (allowlist.length === 0 && NODE_ENV !== 'development') {
    return jsonError('ALIGNMENT_ARTIFACT_HOST_ALLOWLIST must be set outside development', 500);
  }

  if (allowlist.length > 0 && !allowlist.includes(parsed.host)) {
    return jsonError('Alignment artifact host is not allowed', 403);
  }

  const response = await fetch(artifactUrl, { cache: 'no-store' });
  if (!response.ok) return NextResponse.json({ artifact: null }, { headers: { 'Cache-Control': 'no-store' } });

  try {
    const payload = await response.json();
    return NextResponse.json({ artifact: payload }, { headers: { 'Cache-Control': 'no-store' } });
  } catch {
    return jsonError('Alignment artifact payload is not valid JSON', 502);
  }
}

async function handle(request: NextRequest, { params }: { params: { path: string[] } }) {
  const rate = enforceRateLimit(request);
  if (rate) return rate;

  const path = params.path || [];
  if (!path.length) return jsonError('Missing path', 400);
  if (isAlignmentArtifact(path) && request.method === 'GET') return getAlignmentArtifact();
  return proxyToCore(request, path);
}

export async function GET(request: NextRequest, context: { params: { path: string[] } }) {
  return handle(request, context);
}

export async function POST(request: NextRequest, context: { params: { path: string[] } }) {
  return handle(request, context);
}

export async function DELETE(request: NextRequest, context: { params: { path: string[] } }) {
  return handle(request, context);
}

export async function HEAD(request: NextRequest, context: { params: { path: string[] } }) {
  return handle(request, context);
}
