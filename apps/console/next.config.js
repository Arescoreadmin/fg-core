const path = require('path');

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
};

module.exports = nextConfig;
