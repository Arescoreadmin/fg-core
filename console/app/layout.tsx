import type { Metadata } from 'next';
import './globals.css';

export const metadata: Metadata = {
  title: 'FrostGate Console',
  description: 'Administrative console for FrostGate',
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
