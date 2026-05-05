/** @type {import('next').NextConfig} */
const nextConfig = {
  output: 'standalone',

  async rewrites() {
    const assessmentUrl =
      process.env.ASSESSMENT_ENGINE_URL || 'http://assessment-engine:8081';
    const reportUrl =
      process.env.REPORT_ENGINE_URL || 'http://report-engine:8082';

    return [
      {
        source: '/api/:path*',
        destination: 'http://admin-gateway:8080/:path*',
      },
      {
        source: '/assessment-api/:path*',
        destination: `${assessmentUrl}/:path*`,
      },
      {
        source: '/report-api/:path*',
        destination: `${reportUrl}/:path*`,
      },
    ];
  },
};

module.exports = nextConfig;
