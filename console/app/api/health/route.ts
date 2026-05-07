import { NextResponse } from 'next/server';
import { getRateLimitHealth } from '@/lib/rateLimitStore';

export async function GET() {
  const rateLimitStatus = await getRateLimitHealth();

  // Never include Redis URL or credentials in response
  return NextResponse.json({
    status: 'ok',
    service: 'console',
    version: '0.1.0',
    timestamp: new Date().toISOString(),
    rateLimit: rateLimitStatus,
  });
}
