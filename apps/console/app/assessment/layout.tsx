import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'AI Governance Assessment',
  robots: { index: false, follow: false },
};

export default function AssessmentLayout({ children }: { children: React.ReactNode }) {
  return <>{children}</>;
}
