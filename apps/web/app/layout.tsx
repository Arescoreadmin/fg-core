import type { Metadata } from 'next';
import './globals.css';

export const metadata: Metadata = {
  title: 'FrostGate — AI Governance & Compliance',
  description:
    'Field assessment and AI governance platform for compliance-driven organizations. NIST AI RMF, HIPAA, SOC 2, CMMC, and ISO 27001.',
  metadataBase: new URL('https://frostgate.ai'),
  openGraph: {
    title: 'FrostGate — AI Governance & Compliance',
    description:
      'Field assessment and AI governance platform for compliance-driven organizations.',
    url: 'https://frostgate.ai',
    siteName: 'FrostGate',
    type: 'website',
  },
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body className="bg-gray-950 text-gray-100 font-sans antialiased">{children}</body>
    </html>
  );
}
