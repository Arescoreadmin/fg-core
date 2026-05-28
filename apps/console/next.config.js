const path = require('path');

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
  transpilePackages: ['@fg/ui'],

  // Ensure webpack resolves @fg/ui's deps (class-variance-authority, clsx,
  // @radix-ui/*, etc.) from this package's node_modules even when the source
  // files are outside the console directory (e.g. packages/ui in Docker).
  webpack(config) {
    config.resolve.modules = [
      path.resolve(__dirname, 'node_modules'),
      ...config.resolve.modules,
    ];
    return config;
  },

  async rewrites() {
    // All API traffic — including assessment and report endpoints — routes
    // through the single fg-core admin-gateway. No separate assessment or
    // report service processes are needed.
    return [
      {
        source: '/api/:path*',
        destination: 'http://admin-gateway:8080/:path*',
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
