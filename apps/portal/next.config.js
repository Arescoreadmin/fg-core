/** @type {import('next').NextConfig} */
const nextConfig = {
  // Next 15 infers the tracing root from the nearest lockfile set; pin it to
  // this app so build output layout matches Next 14 (Docker/Vercel parity).
  outputFileTracingRoot: __dirname,
  transpilePackages: ['@fg/ui', '@fg/navigation'],
};

module.exports = nextConfig;
