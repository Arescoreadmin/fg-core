import type { Metadata } from 'next';
import './globals.css';

export const metadata: Metadata = {
  title: 'FrostGate',
  description:
    'Field assessment and AI governance platform for compliance-driven organizations. NIST AI RMF, HIPAA, SOC 2, CMMC, ISO 27001.',
  metadataBase: new URL('https://frostgate.ai'),
  openGraph: {
    title: 'FrostGate',
    description: 'Field assessment and AI governance platform.',
    url: 'https://frostgate.ai',
    siteName: 'FrostGate',
    type: 'website',
  },
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body className="bg-bg text-[#f0f0f0] font-sans antialiased">{children}</body>
    </html>
  );
}
