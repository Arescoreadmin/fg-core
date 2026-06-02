export const COOKIE_NAME = 'fg_portal_session';
const SESSION_TTL_MS = 8 * 60 * 60 * 1000; // 8 hours

export interface SessionUser {
  userId: string;
  email: string;
  displayName: string;
  role: string;
}

async function getKey(): Promise<CryptoKey | null> {
  const secret = process.env.PORTAL_SESSION_SECRET;
  if (!secret || secret.length < 16) return null;
  const raw = new TextEncoder().encode(secret);
  return crypto.subtle.importKey('raw', raw, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
}

// ─── Password-only session (legacy, no user identity) ─────────────────────────

export async function createSessionToken(): Promise<string> {
  const key = await getKey();
  if (!key) throw new Error('PORTAL_SESSION_SECRET not configured');
  const exp = Date.now() + SESSION_TTL_MS;
  const payloadB64 = btoa(`ok:${exp}`);
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(payloadB64));
  const sigB64 = btoa(String.fromCharCode(...new Uint8Array(sig)));
  return `${payloadB64}.${sigB64}`;
}

// ─── Access-code session (per-client, carries access code) ────────────────────

export async function createAccessCodeSession(accessCode: string): Promise<string> {
  const key = await getKey();
  if (!key) throw new Error('PORTAL_SESSION_SECRET not configured');
  const exp = Date.now() + SESSION_TTL_MS;
  const payload = JSON.stringify({ ok: true, exp, accessCode });
  const payloadB64 = btoa(unescape(encodeURIComponent(payload)));
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(payloadB64));
  const sigB64 = btoa(String.fromCharCode(...new Uint8Array(sig)));
  return `${payloadB64}.${sigB64}`;
}

export async function getSessionAccessCode(token: string | undefined): Promise<string | null> {
  if (!token) return null;
  const key = await getKey();
  if (!key) return null;
  try {
    const dot = token.indexOf('.');
    if (dot < 1) return null;
    const payloadB64 = token.slice(0, dot);
    const sigB64 = token.slice(dot + 1);
    const sig = Uint8Array.from(atob(sigB64), (c) => c.charCodeAt(0));
    const valid = await crypto.subtle.verify('HMAC', key, sig, new TextEncoder().encode(payloadB64));
    if (!valid) return null;
    const payloadRaw = atob(payloadB64);
    if (payloadRaw.startsWith('ok:')) return null; // legacy password-only session
    const parsed = JSON.parse(decodeURIComponent(escape(payloadRaw)));
    if (!parsed.ok || Date.now() > (parsed.exp ?? 0)) return null;
    return (parsed.accessCode as string) ?? null;
  } catch {
    return null;
  }
}

// ─── User-identity session (invite token login) ───────────────────────────────

export async function createUserSessionToken(user: SessionUser): Promise<string> {
  const key = await getKey();
  if (!key) throw new Error('PORTAL_SESSION_SECRET not configured');
  const exp = Date.now() + SESSION_TTL_MS;
  const payload = JSON.stringify({ ok: true, exp, ...user });
  const payloadB64 = btoa(unescape(encodeURIComponent(payload)));
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(payloadB64));
  const sigB64 = btoa(String.fromCharCode(...new Uint8Array(sig)));
  return `${payloadB64}.${sigB64}`;
}

export async function verifySessionToken(token: string | undefined): Promise<boolean> {
  if (!token) return false;
  const key = await getKey();
  if (!key) return false;
  try {
    const dot = token.indexOf('.');
    if (dot < 1) return false;
    const payloadB64 = token.slice(0, dot);
    const sigB64 = token.slice(dot + 1);
    const payloadRaw = atob(payloadB64);
    const sig = Uint8Array.from(atob(sigB64), (c) => c.charCodeAt(0));
    const valid = await crypto.subtle.verify('HMAC', key, sig, new TextEncoder().encode(payloadB64));
    if (!valid) return false;
    // Support both legacy "ok:{exp}" and JSON payloads
    if (payloadRaw.startsWith('ok:')) {
      const exp = parseInt(payloadRaw.split(':')[1] ?? '0', 10);
      return Date.now() <= exp;
    }
    const parsed = JSON.parse(decodeURIComponent(escape(payloadRaw)));
    return parsed.ok === true && Date.now() <= (parsed.exp ?? 0);
  } catch {
    return false;
  }
}

export async function getSessionUser(token: string | undefined): Promise<SessionUser | null> {
  if (!token) return null;
  const key = await getKey();
  if (!key) return null;
  try {
    const dot = token.indexOf('.');
    if (dot < 1) return null;
    const payloadB64 = token.slice(0, dot);
    const sigB64 = token.slice(dot + 1);
    const sig = Uint8Array.from(atob(sigB64), (c) => c.charCodeAt(0));
    const valid = await crypto.subtle.verify('HMAC', key, sig, new TextEncoder().encode(payloadB64));
    if (!valid) return null;
    const payloadRaw = atob(payloadB64);
    if (payloadRaw.startsWith('ok:')) return null; // password-only session, no user identity
    const parsed = JSON.parse(decodeURIComponent(escape(payloadRaw)));
    if (!parsed.ok || Date.now() > (parsed.exp ?? 0)) return null;
    if (!parsed.userId || !parsed.email) return null;
    return {
      userId: parsed.userId,
      email: parsed.email,
      displayName: parsed.displayName ?? parsed.email,
      role: parsed.role ?? 'user',
    };
  } catch {
    return null;
  }
}
