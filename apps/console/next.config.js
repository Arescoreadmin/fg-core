// Derive just the origin from NEXT_PUBLIC_API_URL so that connect-src allows
// client-side fetches from lib/api.ts to the admin-gateway even when it is
// served on a different host or port than the console (e.g. localhost:18001).
function resolveApiOrigin() {
  const raw = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:18001';
  try {
    return new URL(raw).origin;
  } catch {
    return raw.replace(/\/$/, '');
  }
}

const apiOrigin = resolveApiOrigin();

const cspHeader = [
  "default-src 'none'",
  // Next.js requires unsafe-eval in dev; keep unsafe-inline for injected styles.
  "script-src 'self' 'unsafe-eval' 'unsafe-inline'",
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data: blob:",
  "font-src 'self'",
  // 'self' covers the /api/* proxy path; apiOrigin covers direct admin-gateway
  // fetches from lib/api.ts (products, audit, keys pages).
  `connect-src 'self' ${apiOrigin}`,
  "frame-ancestors 'none'",
].join('; ');

/** @type {import('next').NextConfig} */
const nextConfig = {
  output: 'standalone',
  transpilePackages: ['@fg/ui', '@fg/navigation'],

  async rewrites() {
    // On Vercel, the BFF proxy at /app/api/core/[...path]/route.ts handles all
    // backend traffic with API-key injection, rate limiting, and tenant scoping.
    // The catch-all rewrite is only needed in Docker where admin-gateway routes
    // all /api/* traffic. Without this guard, the rewrite fires before dynamic
    // catch-all routes and intercepts /api/core/* and /api/auth/* on Vercel.
    if (process.env.VERCEL) return [];
    const upstream = (process.env.CORE_API_URL || 'http://admin-gateway:8080').replace(/\/$/, '');
    return [
      {
        source: '/api/:path*',
        destination: `${upstream}/:path*`,
      },
    ];
  },

  async headers() {
    return [
      {
        source: '/(.*)',
        headers: [
          {
            key: 'Content-Security-Policy',
            value: cspHeader,
          },
          {
            key: 'X-Frame-Options',
            value: 'DENY',
          },
          {
            key: 'X-Content-Type-Options',
            value: 'nosniff',
          },
          {
            key: 'Referrer-Policy',
            value: 'strict-origin-when-cross-origin',
          },
        ],
      },
    ];
  },
};

module.exports = nextConfig;
