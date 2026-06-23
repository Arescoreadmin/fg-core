/** @type {import('next').NextConfig} */
const nextConfig = {
  output: 'standalone',

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
