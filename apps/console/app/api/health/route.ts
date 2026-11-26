import { NextResponse } from 'next/server';
import { getRateLimitHealth } from '@/lib/rateLimitStore';
import { resolveLimiterKeyMaterial } from '@/lib/bffRateLimitPolicy';

export async function GET() {
  // Liveness never depends on the limiter: store and key problems are
  // reported in the body, and the route still returns 200.
  const rateLimitStatus = await getRateLimitHealth();
  // FG-849-REPAIR-001: runtime proof that the limiter identity key is usable
  // in this deployment, without exposing it. source is one of 'dedicated' |
  // 'derived-auth-secret' | 'ephemeral-dev'; never the secret or its length.
  const keyMaterial = resolveLimiterKeyMaterial();
  const identityKey = keyMaterial.ok
    ? { ready: true, source: keyMaterial.source }
    : { ready: false, source: null, reason: keyMaterial.reason };

  // Never include Redis URL or credentials in response
  return NextResponse.json({
    status: 'ok',
    service: 'console',
    version: '0.1.0',
    timestamp: new Date().toISOString(),
    rateLimit: { ...rateLimitStatus, identityKey },
  });
}
