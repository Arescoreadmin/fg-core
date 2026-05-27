import type { Metadata, Viewport } from 'next';
import './globals.css';
import { Providers } from '@/lib/providers';

export const viewport: Viewport = {
  width: 'device-width',
  initialScale: 1,
  themeColor: '#05070A',
};

export const metadata: Metadata = {
  metadataBase: new URL(
    process.env.NEXT_PUBLIC_SITE_URL ?? 'https://frostgate.ai'
  ),
  title: {
    default: 'FrostGate — Trust But Verify · AI Governance for Regulated Industries',
    template: '%s · FrostGate',
  },
  description:
    'FrostGate is the AI governance platform for community banking, healthcare, legal, and defense. Assess your AI risk posture, verify compliance, and get a defensible answer for your regulator — starting at $299.',
  keywords: [
    'AI governance',
    'AI risk assessment',
    'NIST AI RMF',
    'HIPAA AI compliance',
    'FFIEC cybersecurity',
    'CMMC compliance',
    'community bank AI policy',
    'healthcare AI governance',
    'trust but verify',
  ],
  authors: [{ name: 'FrostGate' }],
  creator: 'FrostGate',
  robots: {
    index: true,
    follow: true,
    googleBot: { index: true, follow: true },
  },
  openGraph: {
    type: 'website',
    locale: 'en_US',
    siteName: 'FrostGate',
    title: 'FrostGate — Trust But Verify · AI Governance for Regulated Industries',
    description:
      'The AI governance platform built for regulated industries. Assess, score, and verify your AI risk posture — starting at $299.',
  },
  twitter: {
    card: 'summary_large_image',
    title: 'FrostGate — Trust But Verify',
    description:
      'AI governance for community banking, healthcare, legal, and defense. NIST AI RMF · HIPAA · FFIEC · CMMC.',
  },
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        <Providers>{children}</Providers>
      </body>
    </html>
  );
}
