function isSafeDevHost(hostname: string): boolean {
  return hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '[::1]';
}

function normalizeAbsoluteOrigin(raw: string, label: string): string {
  const trimmed = raw.trim();
  if (!trimmed) {
    throw new Error(`${label} is empty.`);
  }

  const withProtocol = /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
  const parsed = new URL(withProtocol);
  return parsed.origin;
}

function getConfiguredConsoleOrigin(): string | null {
  const candidates: Array<[string, string | undefined]> = [
    ['CONSOLE_BASE_URL', process.env.CONSOLE_BASE_URL],
    ['NEXTAUTH_URL', process.env.NEXTAUTH_URL],
    ['NEXT_PUBLIC_APP_URL', process.env.NEXT_PUBLIC_APP_URL],
    ['VERCEL_URL', process.env.VERCEL_URL ? `https://${process.env.VERCEL_URL}` : undefined],
  ];

  for (const [label, raw] of candidates) {
    if (!raw) {
      continue;
    }

    const origin = normalizeAbsoluteOrigin(raw, label);
    if (
      label === 'CONSOLE_BASE_URL' &&
      (process.env.NODE_ENV || 'development') === 'development' &&
      !isSafeDevHost(new URL(origin).hostname)
    ) {
      throw new Error('CONSOLE_BASE_URL must point to loopback in development.');
    }
    return origin;
  }

  return null;
}

export async function resolveConsoleOrigin(): Promise<string> {
  const configuredOrigin = getConfiguredConsoleOrigin();
  if (configuredOrigin) {
    return configuredOrigin;
  }

  const { headers } = await import('next/headers');
  const headerStore = headers();
  const host = headerStore.get('x-forwarded-host') || headerStore.get('host');
  const proto = headerStore.get('x-forwarded-proto') || 'http';

  if (!host) {
    throw new Error(
      'Console origin is not configured. Set CONSOLE_BASE_URL or NEXTAUTH_URL for server-side /api fetches.',
    );
  }

  return normalizeAbsoluteOrigin(`${proto}://${host}`, 'request host');
}

export async function resolveConsoleUrl(path: string): Promise<string> {
  if (!path.startsWith('/')) {
    throw new Error(`Console URL paths must start with "/": ${path}`);
  }

  if (typeof window !== 'undefined') {
    return path;
  }

  return new URL(path, await resolveConsoleOrigin()).toString();
}
