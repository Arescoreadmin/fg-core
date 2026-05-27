const path = require('path');

const isDev = process.env.NODE_ENV === 'development';

// ─── Content-Security-Policy ──────────────────────────────────────────────────
//
// 'unsafe-inline' on script-src is required by Next.js 14 App Router
// hydration scripts embedded directly in HTML. Upgrade path: add
// middleware-based per-request nonce injection to eliminate 'unsafe-inline'.
//
// When Stripe is wired (Stage 1), add to the relevant directives:
//   script-src: https://js.stripe.com
//   frame-src:  https://js.stripe.com
//   connect-src: https://api.stripe.com
//
const cspDirectives = [
  "default-src 'self'",
  `script-src 'self' 'unsafe-inline'${isDev ? " 'unsafe-eval'" : ''}`,
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data: blob:",
  "font-src 'self'",
  "connect-src 'self'",
  "media-src 'none'",
  "object-src 'none'",
  "frame-src 'none'",
  "frame-ancestors 'none'",
  "base-uri 'self'",
  "form-action 'self'",
  !isDev && "upgrade-insecure-requests",
]
  .filter(Boolean)
  .join('; ');

// ─── Security headers (applied to every response) ─────────────────────────────
const SECURITY_HEADERS = [
  // Prevent browsers from MIME-sniffing the content-type
  { key: 'X-Content-Type-Options', value: 'nosniff' },
  // Disallow embedding in iframes entirely (clickjacking)
  { key: 'X-Frame-Options', value: 'DENY' },
  // Restrict referrer to same-origin for cross-origin navigations
  { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
  // Disable browser features not used by this app
  {
    key: 'Permissions-Policy',
    value: [
      'camera=()',
      'microphone=()',
      'geolocation=()',
      'payment=()',
      'usb=()',
      'interest-cohort=()',
      'browsing-topics=()',
      'display-capture=()',
    ].join(', '),
  },
  // Prevent DNS prefetch leaking visited paths
  { key: 'X-DNS-Prefetch-Control', value: 'off' },
  // Prevent IE/Edge from opening downloads in-process
  { key: 'X-Download-Options', value: 'noopen' },
  // Block Flash/PDF cross-domain data loading
  { key: 'X-Permitted-Cross-Domain-Policies', value: 'none' },
  // CSP (constructed above)
  { key: 'Content-Security-Policy', value: cspDirectives },
  // HSTS: 2-year max-age, enabled only outside dev (requires valid TLS cert)
  ...(!isDev
    ? [
        {
          key: 'Strict-Transport-Security',
          value: 'max-age=63072000; includeSubDomains; preload',
        },
      ]
    : []),
];

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

  async headers() {
    return [
      {
        // Apply security headers to every route
        source: '/:path*',
        headers: SECURITY_HEADERS,
      },
      {
        // Extra cache control on API proxy responses — never cache sensitive data
        source: '/api/:path*',
        headers: [
          ...SECURITY_HEADERS,
          { key: 'Cache-Control', value: 'no-store, no-cache, must-revalidate, proxy-revalidate' },
          { key: 'Pragma', value: 'no-cache' },
          { key: 'Expires', value: '0' },
          { key: 'Surrogate-Control', value: 'no-store' },
        ],
      },
    ];
  },

  async rewrites() {
    // All API traffic routes through the single fg-core admin-gateway.
    // In production the gateway should be reached over TLS; update this
    // destination when deploying behind a reverse proxy or with cert pinning.
    return [
      {
        source: '/api/:path*',
        destination: 'http://admin-gateway:8080/:path*',
      },
    ];
  },
};

module.exports = nextConfig;
