import { NextRequest, NextResponse } from 'next/server';
import { createGrantSession, COOKIE_NAME } from '@/lib/session';

const IS_PROD = process.env.NODE_ENV === 'production';

const _loginAttempts = new Map<string, { count: number; resetAt: number }>();
const LOGIN_RL_WINDOW_MS = 15 * 60 * 1000;
const LOGIN_RL_MAX = 5;

function checkLoginRateLimit(ip: string): boolean {
  const now = Date.now();
  const entry = _loginAttempts.get(ip);
  if (!entry || now >= entry.resetAt) {
    _loginAttempts.set(ip, { count: 1, resetAt: now + LOGIN_RL_WINDOW_MS });
    return true;
  }
  entry.count += 1;
  return entry.count <= LOGIN_RL_MAX;
}

function clearLoginAttempts(ip: string) {
  _loginAttempts.delete(ip);
}

export async function POST(req: NextRequest) {
  const sessionSecret = process.env.PORTAL_SESSION_SECRET;
  const coreApiUrl = (process.env.CORE_API_URL || '').replace(/\/$/, '');
  const coreApiKey = process.env.CORE_API_KEY;
  const coreTenantId = process.env.CORE_TENANT_ID;

  if (!sessionSecret || !coreApiUrl || !coreApiKey || !coreTenantId) {
    return NextResponse.json(
      { error: 'Portal authentication is not configured.' },
      { status: 503 },
    );
  }

  const clientIp =
    req.headers.get('x-real-ip') ||
    req.headers.get('x-forwarded-for')?.split(',')[0]?.trim() ||
    'unknown';

  if (!checkLoginRateLimit(clientIp)) {
    return NextResponse.json(
      { error: 'Too many login attempts. Try again in a few minutes.' },
      { status: 429 },
    );
  }

  let body: { password?: string };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: 'Invalid request.' }, { status: 400 });
  }

  const secret = (body.password ?? '').trim();
  if (!secret) {
    return NextResponse.json({ error: 'Access secret is required.' }, { status: 401 });
  }

  // Exchange secret for a server-side session via POST /portal/authenticate.
  // The backend validates against Argon2id hashes — no plaintext stored.
  let sessionId: string;
  try {
    const resp = await fetch(`${coreApiUrl}/portal/authenticate`, {
      method: 'POST',
      headers: {
        'X-API-Key': coreApiKey,
        'X-Tenant-ID': coreTenantId,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ secret }),
      cache: 'no-store',
    });
    if (resp.status === 429) {
      return NextResponse.json(
        { error: 'Too many login attempts. Try again in a few minutes.' },
        { status: 429 },
      );
    }
    if (!resp.ok) {
      return NextResponse.json({ error: 'Invalid access secret.' }, { status: 401 });
    }
    const data = await resp.json();
    sessionId = data.session_id as string;
    if (!sessionId) throw new Error('no session_id in response');
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    if (msg.includes('401') || msg.includes('Invalid')) {
      return NextResponse.json({ error: 'Invalid access secret.' }, { status: 401 });
    }
    return NextResponse.json({ error: 'Authentication service unavailable.' }, { status: 503 });
  }

  clearLoginAttempts(clientIp);
  // Store the opaque backend session_id in a signed HMAC cookie.
  const token = await createGrantSession(sessionId);
  const res = NextResponse.json({ ok: true });
  res.cookies.set(COOKIE_NAME, token, {
    httpOnly: true,
    secure: IS_PROD,
    sameSite: 'lax',
    maxAge: 8 * 60 * 60,
    path: '/',
  });
  return res;
}
