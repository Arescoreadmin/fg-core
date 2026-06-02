import { NextRequest, NextResponse } from 'next/server';
import { createAccessCodeSession, COOKIE_NAME } from '@/lib/session';

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
  const secret = process.env.PORTAL_SESSION_SECRET;
  const coreApiUrl = (process.env.CORE_API_URL || '').replace(/\/$/, '');
  const coreApiKey = process.env.CORE_API_KEY;
  const coreTenantId = process.env.CORE_TENANT_ID;

  if (!secret || !coreApiUrl || !coreApiKey || !coreTenantId) {
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

  const accessCode = (body.password ?? '').trim().toUpperCase();
  if (!accessCode) {
    return NextResponse.json({ error: 'Access code is required.' }, { status: 401 });
  }

  // Validate: check that at least one engagement exists for this access code.
  try {
    const resp = await fetch(
      `${coreApiUrl}/field-assessment/engagements?client_access_code=${encodeURIComponent(accessCode)}&limit=1`,
      {
        headers: {
          'X-API-Key': coreApiKey,
          'X-Tenant-ID': coreTenantId,
          'X-Portal-Source': 'client-portal-auth',
        },
        cache: 'no-store',
      },
    );
    if (!resp.ok) throw new Error(`backend ${resp.status}`);
    const data = await resp.json();
    if (!Array.isArray(data.items) || data.items.length === 0) {
      return NextResponse.json({ error: 'Invalid access code.' }, { status: 401 });
    }
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    if (msg.includes('401') || msg.includes('Invalid')) {
      return NextResponse.json({ error: 'Invalid access code.' }, { status: 401 });
    }
    return NextResponse.json({ error: 'Authentication service unavailable.' }, { status: 503 });
  }

  clearLoginAttempts(clientIp);
  const token = await createAccessCodeSession(accessCode);
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
