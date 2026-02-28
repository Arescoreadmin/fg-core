/** @type {import('next').NextConfig} */
const nextConfig = {
  output: "standalone",

  async rewrites() {
    return [
      {
        source: "/api/:path*",
        destination: "http://admin-gateway:8080/:path*",
      },
    ];
  },
};

module.exports = nextConfig;