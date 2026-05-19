/** @type {import('next').NextConfig} */
const nextConfig = {
  output: 'standalone',
  transpilePackages: ['@fg/ui'],

  async rewrites() {
    return [
      {
        source: '/api/:path*',
        destination: 'http://admin-gateway:8080/:path*',
      },
    ];
  },
};

module.exports = nextConfig;
