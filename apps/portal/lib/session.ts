export const COOKIE_NAME = 'fg_portal_session';
const SESSION_TTL_MS = 8 * 60 * 60 * 1000; // 8 hours

async function getKey(): Promise<CryptoKey | null> {
  const secret = process.env.PORTAL_SESSION_SECRET;
  if (!secret || secret.length < 16) return null;
  const raw = new TextEncoder().encode(secret);
  return crypto.subtle.importKey('raw', raw, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
}

export async function createSessionToken(): Promise<string> {
  const key = await getKey();
  if (!key) throw new Error('PORTAL_SESSION_SECRET not configured');
  const exp = Date.now() + SESSION_TTL_MS;
  const payload = `ok:${exp}`;
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(payload));
  const sigB64 = btoa(String.fromCharCode(...new Uint8Array(sig)));
  return `${btoa(payload)}.${sigB64}`;
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
    const payload = atob(payloadB64);
    const sig = Uint8Array.from(atob(sigB64), (c) => c.charCodeAt(0));
    const valid = await crypto.subtle.verify('HMAC', key, sig, new TextEncoder().encode(payload));
    if (!valid) return false;
    const exp = parseInt(payload.split(':')[1] ?? '0', 10);
    return Date.now() <= exp;
  } catch {
    return false;
  }
}
