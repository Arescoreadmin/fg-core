import { NextResponse } from 'next/server';
import { getBffRateLimitConfig, getRateLimitStore } from '@/lib/rateLimitStore';

export async function GET() {
  const config = getBffRateLimitConfig();
  const storeResult = await getRateLimitStore();

  const rateLimitStatus = {
    backend: config.backend,
    ready: !storeResult.unavailable,
    // "required" is true when Redis was required (prod-like) but unavailable
    required: storeResult.unavailable ? storeResult.required : false,
    // stable error code distinguishes config-missing from transient Redis failure
    reason: storeResult.unavailable ? storeResult.errorCode : null,
  };

  // Never include Redis URL or credentials in response
  return NextResponse.json({
    status: 'ok',
    service: 'console',
    version: '0.1.0',
    timestamp: new Date().toISOString(),
    rateLimit: rateLimitStatus,
  });
}
