import Link from 'next/link';
import {
  Shield,
  Zap,
  Lock,
  BarChart3,
  FileCheck,
  Users,
  ArrowRight,
  CheckCircle2,
  AlertTriangle,
  Building2,
  HeartPulse,
  Gavel,
  HardHat,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';

const TIERS = [
  {
    name: 'Snapshot',
    price: '$299',
    period: 'one-time',
    description: 'Guided AI risk assessment + advisory PDF report for your leadership team.',
    badge: null,
    cta: 'Start Assessment',
    href: '/onboarding',
    features: [
      'AI governance assessment (35–130 questions)',
      'Risk scoring across 6 domains',
      'AI-generated executive report (PDF)',
      '30/60/90 day remediation roadmap',
      'Compliance framework alignment',
    ],
  },
  {
    name: 'Intelligence',
    price: '$5,000',
    period: 'per year',
    description: 'Continuous monitoring, benchmarking, and RAG-grounded recommendations.',
    badge: 'Most Popular',
    cta: 'Get Intelligence',
    href: '/onboarding?tier=intelligence',
    features: [
      'Everything in Snapshot',
      'Live compliance dashboard',
      'Industry benchmarking',
      'Policy-grounded RAG recommendations',
      'Multi-user RBAC (exec/auditor/admin)',
      'Assessment delegation',
    ],
  },
  {
    name: 'Control',
    price: '$50,000',
    period: 'per year',
    description: 'Runtime AI gateway — every model request classified, policy-checked, audited.',
    badge: 'Enterprise',
    cta: 'Talk to Sales',
    href: 'mailto:sales@frostgate.ai',
    features: [
      'Everything in Intelligence',
      'Drop-in Anthropic/OpenAI proxy',
      'Real-time OPA policy enforcement',
      'PII/PHI/CUI tokenization at AI boundary',
      'Provider routing by classification',
      'HMAC-chained forensic audit log',
    ],
  },
  {
    name: 'Autonomous',
    price: '$100,000',
    period: 'per year',
    description: 'Continuous monitoring, drift detection, and auto-remediation at scale.',
    badge: null,
    cta: 'Talk to Sales',
    href: 'mailto:sales@frostgate.ai',
    features: [
      'Everything in Control',
      'Continuous risk monitoring',
      'Drift detection + alerting',
      'Auto-remediation suggestions',
      'Predictive risk modeling',
      'Custom compliance modules',
    ],
  },
];

const INDUSTRIES = [
  { icon: Building2, label: 'Community Banking', note: 'FFIEC CAT · SR 11-7 · GLBA' },
  { icon: HeartPulse, label: 'Healthcare', note: 'HIPAA · HITRUST · HHS OCR' },
  { icon: Gavel, label: 'Legal', note: 'Florida Bar 4-1.6 · ABA 512' },
  { icon: HardHat, label: 'Defense Contractors', note: 'CMMC 2.0 · NIST 800-171 · DFARS' },
];

const FEATURES = [
  {
    icon: Shield,
    title: 'Policy-Aware Assessment',
    description:
      'Profile-driven questionnaires that match your org size, industry, and regulatory exposure. No generic checklists.',
  },
  {
    icon: Zap,
    title: 'AI-Generated Reports',
    description:
      'Claude-powered advisory reports in executive, technical, and compliance variants — always with a 30/60/90 day roadmap.',
  },
  {
    icon: Lock,
    title: 'Runtime Gateway',
    description:
      'Drop-in proxy that classifies every AI request, enforces OPA policies, tokenizes PII/PHI, and logs with HMAC-chain integrity.',
  },
  {
    icon: BarChart3,
    title: 'Compliance Mapping',
    description:
      'Automatic alignment scoring across NIST AI RMF, SOC 2, HIPAA, FFIEC CAT, CMMC 2.0, and 10+ other frameworks.',
  },
  {
    icon: FileCheck,
    title: 'Forensic Audit Log',
    description:
      'Append-only, HMAC-chained audit trail. Tamper-evident by construction — holds up in examiner review.',
  },
  {
    icon: Users,
    title: 'Multi-Tenant RBAC',
    description:
      'Role-scoped access for exec, auditor, admin, operator, and viewer. Built for regulated environments with audit delegation.',
  },
];

export default function LandingPage() {
  return (
    <div className="min-h-screen bg-background text-foreground">
      {/* Nav */}
      <nav className="sticky top-0 z-50 border-b border-border bg-background/80 backdrop-blur-md">
        <div className="mx-auto flex h-16 max-w-6xl items-center justify-between px-6">
          <div className="flex items-center gap-2">
            <div className="flex h-7 w-7 items-center justify-center rounded bg-primary">
              <Zap className="h-4 w-4 text-white" />
            </div>
            <span className="font-semibold text-foreground">FrostGate</span>
          </div>
          <div className="hidden items-center gap-6 text-sm text-muted md:flex">
            <a href="#features" className="hover:text-foreground transition-colors">Features</a>
            <a href="#pricing" className="hover:text-foreground transition-colors">Pricing</a>
            <a href="#industries" className="hover:text-foreground transition-colors">Industries</a>
          </div>
          <div className="flex items-center gap-3">
            <Link href="/dashboard">
              <Button variant="outline" size="sm">Sign In</Button>
            </Link>
            <Link href="/onboarding">
              <Button size="sm">Get Started</Button>
            </Link>
          </div>
        </div>
      </nav>

      {/* Hero */}
      <section className="mx-auto max-w-6xl px-6 pt-24 pb-20 text-center">
        <div className="mb-4 inline-flex items-center gap-2 rounded-full border border-primary/30 bg-primary/5 px-4 py-1.5 text-xs text-primary">
          <AlertTriangle className="h-3 w-3" />
          Your team is using AI without governance. Every community bank, medical group, and law firm has this problem.
        </div>

        <h1 className="mt-6 text-4xl font-bold tracking-tight text-foreground sm:text-5xl lg:text-6xl">
          AI Governance for{' '}
          <span className="text-primary">Regulated Industries</span>
        </h1>

        <p className="mt-6 mx-auto max-w-2xl text-lg text-muted leading-relaxed">
          FrostGate is the only AI governance platform built specifically for community banking,
          healthcare, legal, and defense — the industries where the stakes are highest and the
          options are fewest.
        </p>

        <div className="mt-10 flex flex-col items-center gap-4 sm:flex-row sm:justify-center">
          <Link href="/onboarding">
            <Button size="lg" className="gap-2">
              Start Free Assessment <ArrowRight className="h-4 w-4" />
            </Button>
          </Link>
          <Link href="/dashboard">
            <Button variant="outline" size="lg">View Demo Dashboard</Button>
          </Link>
        </div>

        <p className="mt-4 text-xs text-muted">No credit card required for Snapshot assessment</p>
      </section>

      {/* Risk callout */}
      <section className="mx-auto max-w-6xl px-6 pb-16">
        <div className="rounded-xl border border-danger/20 bg-danger/5 p-8 text-center">
          <h2 className="text-xl font-semibold text-foreground mb-3">
            The average community bank assessment scores <span className="text-danger">38/100</span> — High Risk
          </h2>
          <p className="text-muted text-sm max-w-xl mx-auto">
            Staff are using ChatGPT with customer NPI. No policy. No audit trail. No examiner answer.
            Regulators are asking. FrostGate gives you a defensible answer in 48 hours.
          </p>
        </div>
      </section>

      {/* Features */}
      <section id="features" className="mx-auto max-w-6xl px-6 py-16">
        <div className="mb-12 text-center">
          <h2 className="text-2xl font-bold text-foreground">Platform capabilities</h2>
          <p className="mt-3 text-muted">Four tiers. One platform. Assessment through runtime control.</p>
        </div>
        <div className="grid gap-6 sm:grid-cols-2 lg:grid-cols-3">
          {FEATURES.map((f) => (
            <Card key={f.title} className="hover:border-primary/30 transition-colors">
              <CardHeader>
                <div className="mb-3 flex h-9 w-9 items-center justify-center rounded-lg bg-primary/10">
                  <f.icon className="h-5 w-5 text-primary" />
                </div>
                <CardTitle>{f.title}</CardTitle>
              </CardHeader>
              <CardContent>
                <CardDescription className="text-sm leading-relaxed">{f.description}</CardDescription>
              </CardContent>
            </Card>
          ))}
        </div>
      </section>

      {/* Industries */}
      <section id="industries" className="bg-surface py-16">
        <div className="mx-auto max-w-6xl px-6">
          <div className="mb-10 text-center">
            <h2 className="text-2xl font-bold text-foreground">Built for regulated industries</h2>
            <p className="mt-3 text-muted">Compliance frameworks and scoring weights pre-tuned per vertical.</p>
          </div>
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
            {INDUSTRIES.map((ind) => (
              <div
                key={ind.label}
                className="rounded-lg border border-border bg-surface-2 p-5 hover:border-primary/30 transition-colors"
              >
                <ind.icon className="h-6 w-6 text-primary mb-3" />
                <p className="font-medium text-foreground text-sm">{ind.label}</p>
                <p className="mt-1 text-xs text-muted">{ind.note}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Pricing */}
      <section id="pricing" className="mx-auto max-w-6xl px-6 py-16">
        <div className="mb-12 text-center">
          <h2 className="text-2xl font-bold text-foreground">Simple, transparent pricing</h2>
          <p className="mt-3 text-muted">Start with a Snapshot. Scale to Control when you need it.</p>
        </div>
        <div className="grid gap-6 lg:grid-cols-4">
          {TIERS.map((tier) => (
            <div
              key={tier.name}
              className={`relative rounded-xl border p-6 flex flex-col ${
                tier.badge === 'Most Popular'
                  ? 'border-primary bg-primary/5'
                  : 'border-border bg-surface'
              }`}
            >
              {tier.badge && (
                <Badge
                  variant={tier.badge === 'Most Popular' ? 'default' : 'secondary'}
                  className="absolute -top-3 left-1/2 -translate-x-1/2"
                >
                  {tier.badge}
                </Badge>
              )}
              <div className="mb-4">
                <p className="text-sm font-medium text-muted">{tier.name}</p>
                <div className="mt-1 flex items-baseline gap-1">
                  <span className="text-2xl font-bold text-foreground">{tier.price}</span>
                  <span className="text-xs text-muted">{tier.period}</span>
                </div>
                <p className="mt-2 text-xs text-muted leading-relaxed">{tier.description}</p>
              </div>

              <ul className="flex-1 space-y-2 mb-6">
                {tier.features.map((f) => (
                  <li key={f} className="flex items-start gap-2 text-xs text-foreground">
                    <CheckCircle2 className="h-3.5 w-3.5 text-primary shrink-0 mt-0.5" />
                    {f}
                  </li>
                ))}
              </ul>

              <Link href={tier.href}>
                <Button
                  variant={tier.badge === 'Most Popular' ? 'default' : 'outline'}
                  className="w-full"
                  size="sm"
                >
                  {tier.cta}
                </Button>
              </Link>
            </div>
          ))}
        </div>
      </section>

      {/* CTA */}
      <section className="bg-surface py-16">
        <div className="mx-auto max-w-2xl px-6 text-center">
          <h2 className="text-2xl font-bold text-foreground">
            Your regulators are already asking about AI governance.
          </h2>
          <p className="mt-4 text-muted">
            Get a defensible risk posture in 48 hours — starting at $299. No enterprise contract
            required to know where you stand.
          </p>
          <Link href="/onboarding" className="mt-8 inline-block">
            <Button size="lg" className="gap-2">
              Start Your Assessment <ArrowRight className="h-4 w-4" />
            </Button>
          </Link>
        </div>
      </section>

      {/* Footer */}
      <footer className="border-t border-border py-8">
        <div className="mx-auto max-w-6xl px-6 flex flex-col items-center gap-2 sm:flex-row sm:justify-between">
          <div className="flex items-center gap-2">
            <div className="flex h-6 w-6 items-center justify-center rounded bg-primary">
              <Zap className="h-3.5 w-3.5 text-white" />
            </div>
            <span className="text-sm font-medium text-foreground">FrostGate</span>
          </div>
          <p className="text-xs text-muted">
            &copy; {new Date().getFullYear()} FrostGate. AI Governance for Regulated Industries.
          </p>
          <p className="text-xs text-muted/60">
            Aligned with, not certified to, NIST AI RMF · HIPAA · FFIEC · CMMC
          </p>
        </div>
      </footer>
    </div>
  );
}
