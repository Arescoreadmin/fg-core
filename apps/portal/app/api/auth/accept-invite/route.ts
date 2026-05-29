import { NextRequest, NextResponse } from 'next/server';
import { COOKIE_NAME, createUserSessionToken, type SessionUser } from '@/lib/session';

const CORE_API_URL = (process.env.CORE_API_URL || 'http://localhost:8000').replace(/\/$/, '');
const CORE_API_KEY = process.env.CORE_API_KEY!;
const CORE_TENANT_ID = process.env.CORE_TENANT_ID!;

export async function POST(request: NextRequest) {
  const body = await request.json().catch(() => ({}));
  const token = (body?.invite_token ?? '').trim();

  if (!token) {
    return NextResponse.json({ error: 'invite_token is required' }, { status: 400 });
  }

  // Exchange the invite token with the backend
  const upstream = await fetch(`${CORE_API_URL}/workforce/users/accept-invite`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-API-Key': CORE_API_KEY,
      'X-Tenant-ID': CORE_TENANT_ID,
    },
    body: JSON.stringify({ invite_token: token }),
    cache: 'no-store',
  });

  if (!upstream.ok) {
    const err = await upstream.json().catch(() => ({}));
    return NextResponse.json(
      { error: err?.detail ?? 'Invalid or expired invite link.' },
      { status: upstream.status },
    );
  }

  const user = await upstream.json() as {
    user_id: string;
    email: string;
    display_name: string;
    role: string;
  };

  const sessionUser: SessionUser = {
    userId: user.user_id,
    email: user.email,
    displayName: user.display_name,
    role: user.role,
  };

  const sessionToken = await createUserSessionToken(sessionUser);

  const response = NextResponse.json({ ok: true, display_name: user.display_name });
  response.cookies.set(COOKIE_NAME, sessionToken, {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    path: '/',
    maxAge: 8 * 60 * 60,
  });
  return response;
}
