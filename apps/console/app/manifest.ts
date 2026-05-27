import type { MetadataRoute } from 'next';

export default function manifest(): MetadataRoute.Manifest {
  return {
    name: 'FrostGate — Trust But Verify',
    short_name: 'FrostGate',
    description:
      'AI governance for regulated industries. Assess, score, and verify your AI risk posture.',
    start_url: '/',
    display: 'standalone',
    background_color: '#05070A',
    theme_color: '#05070A',
    icons: [
      {
        src: '/icon.svg',
        sizes: 'any',
        type: 'image/svg+xml',
        purpose: 'any',
      },
      {
        src: '/icon.svg',
        sizes: 'any',
        type: 'image/svg+xml',
        purpose: 'maskable',
      },
    ],
  };
}
