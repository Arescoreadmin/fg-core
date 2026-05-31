import Redis from 'ioredis';

let _client: Redis | null = null;
let _unavailable = false;

export function getRedisClient(): Redis | null {
  if (_unavailable) return null;
  const url = process.env.PORTAL_REDIS_URL;
  if (!url) return null;
  if (!_client) {
    _client = new Redis(url, {
      lazyConnect: true,
      maxRetriesPerRequest: 1,
      enableOfflineQueue: false,
      connectTimeout: 2000,
    });
    _client.on('error', () => {
      _unavailable = true;
      _client = null;
    });
  }
  return _client;
}
