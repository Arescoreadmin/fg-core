import { NextRequest, NextResponse } from 'next/server';
import { createSessionToken, COOKIE_NAME } from '@/lib/session';

const IS_PROD = process.env.NODE_ENV === 'production';

// 5 failed attempts per IP within 15 minutes triggers a lockout.
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

function timingSafeEqual(a: string, b: string): boolean {
  const ea = new TextEncoder().encode(a);
  const eb = new TextEncoder().encode(b);
  if (ea.length !== eb.length) return false;
  let diff = 0;
  for (let i = 0; i < ea.length; i++) diff |= ea[i] ^ eb[i];
  return diff === 0;
}

export async function POST(req: NextRequest) {
  const password = process.env.PORTAL_PASSWORD;
  const secret = process.env.PORTAL_SESSION_SECRET;

  if (!password || !secret) {
    return NextResponse.json(
      { error: 'Portal authentication is not configured. Set PORTAL_PASSWORD and PORTAL_SESSION_SECRET.' },
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

  if (!timingSafeEqual(body.password ?? '', password)) {
    return NextResponse.json({ error: 'Invalid password.' }, { status: 401 });
  }

  clearLoginAttempts(clientIp);
  const token = await createSessionToken();
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
