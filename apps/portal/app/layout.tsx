import type { Metadata } from 'next';
import './globals.css';

export const metadata: Metadata = {
  title: 'FrostGate — Client Portal',
  description: 'AI governance assessment results and remediation tracking.',
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
