/** @type {import('next').NextConfig} */
const nextConfig = {
  output: 'standalone',

  // Environment variables available to the client
  env: {
    NEXT_PUBLIC_API_URL: process.env.NEXT_PUBLIC_API_URL || 'http://localhost:18001',
  },

  // Disable x-powered-by header
  poweredByHeader: false,

  // Enable strict mode for React
  reactStrictMode: true,
};

module.exports = nextConfig;
