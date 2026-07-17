import { getRedisClient } from '@/lib/redis';

export async function GET() {
  const redisUrl = process.env.PORTAL_REDIS_URL || process.env.REDIS_URL;
  const redis = getRedisClient();

  let redisStatus: 'ok' | 'degraded' | 'unavailable' | 'not_configured';
  if (!redisUrl) {
    redisStatus = 'not_configured';
  } else if (!redis) {
    // Client was created but the error handler already fired and cleared it
    redisStatus = 'unavailable';
  } else {
    try {
      await redis.ping();
      redisStatus = 'ok';
    } catch {
      redisStatus = 'degraded';
    }
  }

  // Redis is a non-critical dependency — portal degrades gracefully without it.
  // status is always 'ok'; redis field gives operators visibility into the store.
  return Response.json({ status: 'ok', redis: redisStatus });
}

export async function HEAD() {
  return new Response(null, { status: 200 });
}
