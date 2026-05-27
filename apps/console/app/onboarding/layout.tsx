import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'Start Your AI Governance Assessment',
  description:
    'Complete a 4-step profile to receive a tailored AI risk assessment for your organization. Pricing from $299 — no credit card required to start.',
  alternates: {
    canonical: 'https://frostgate.ai/onboarding',
  },
  openGraph: {
    title: 'Start Your AI Governance Assessment — FrostGate',
    description:
      'Profile your organization in 4 steps and receive a risk score across 6 AI governance domains, a Claude-powered advisory report, and a 30/60/90-day roadmap.',
    url: 'https://frostgate.ai/onboarding',
  },
};

export default function OnboardingLayout({ children }: { children: React.ReactNode }) {
  return <>{children}</>;
}
