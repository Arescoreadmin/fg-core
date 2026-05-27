'use client';

import { useState } from 'react';
import Link from 'next/link';
import {
  Shield,
  BrainCircuit,
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
  Menu,
  X,
  Search,
  ScanLine,
  ClipboardCheck,
} from 'lucide-react';
import { FrostGateShield } from '@/components/governance/FrostGateShield';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';

// ─── Data ─────────────────────────────────────────────────────────────────────

const FRAMEWORKS = [
  'NIST AI RMF',
  'HIPAA + HHS OCR',
  'FFIEC CAT',
  'CMMC 2.0',
  'SOC 2 Type II',
  'ISO 27001',
  'NIST 800-171',
  'DFARS',
];

const HOW_IT_WORKS = [
  {
    step: '01',
    icon: ScanLine,
    title: 'Assess',
    description:
      'Complete a profile-tuned questionnaire — 35 to 130 questions calibrated to your industry, size, and regulatory exposure. No generic checklists.',
    color: 'text-info',
    bg: 'bg-info/10 border-info/20',
  },
  {
    step: '02',
    icon: BarChart3,
    title: 'Score',
    description:
      'Receive a risk score across 6 governance domains — data governance, security posture, AI maturity, infra readiness, compliance awareness, and automation potential.',
    color: 'text-warning',
    bg: 'bg-warning/10 border-warning/20',
  },
  {
    step: '03',
    icon: ClipboardCheck,
    title: 'Verify',
    description:
      'Get a Claude-powered advisory report with a 30/60/90-day roadmap and framework alignment percentages — a defensible answer for when your regulator asks.',
    color: 'text-primary',
    bg: 'bg-primary/10 border-primary/20',
  },
];

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
    icon: BrainCircuit,
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

const NAV_LINKS = [
  { label: 'How It Works', href: '#how-it-works' },
  { label: 'Features', href: '#features' },
  { label: 'Pricing', href: '#pricing' },
  { label: 'Industries', href: '#industries' },
];

// ─── Component ────────────────────────────────────────────────────────────────

export default function LandingPage() {
  const [mobileOpen, setMobileOpen] = useState(false);

  return (
    <div className="min-h-screen bg-background text-foreground">

      {/* ── Nav ──────────────────────────────────────────────────────────── */}
      <nav className="sticky top-0 z-50 border-b border-border bg-background/90 backdrop-blur-md">
        <div className="mx-auto flex h-16 max-w-6xl items-center justify-between px-6">
          {/* Wordmark */}
          <Link href="/" className="flex items-center gap-2.5 group">
            <FrostGateShield size={28} />
            <div className="flex flex-col leading-none">
              <span className="font-semibold text-foreground text-sm tracking-wide">FrostGate</span>
              <span className="text-[10px] text-muted tracking-widest uppercase">
                Trust But Verify
              </span>
            </div>
          </Link>

          {/* Desktop links */}
          <div className="hidden items-center gap-6 text-sm text-muted md:flex">
            {NAV_LINKS.map((l) => (
              <a key={l.label} href={l.href} className="hover:text-foreground transition-colors">
                {l.label}
              </a>
            ))}
          </div>

          {/* Desktop CTAs */}
          <div className="hidden md:flex items-center gap-3">
            <Link href="/dashboard">
              <Button variant="outline" size="sm">Sign In</Button>
            </Link>
            <Link href="/onboarding">
              <Button size="sm">Get Started</Button>
            </Link>
          </div>

          {/* Mobile hamburger */}
          <button
            className="md:hidden flex items-center justify-center h-9 w-9 rounded border border-border text-muted hover:text-foreground transition-colors"
            onClick={() => setMobileOpen((v) => !v)}
            aria-label={mobileOpen ? 'Close menu' : 'Open menu'}
            aria-expanded={mobileOpen}
          >
            {mobileOpen ? <X className="h-4 w-4" /> : <Menu className="h-4 w-4" />}
          </button>
        </div>

        {/* Mobile dropdown */}
        {mobileOpen && (
          <div className="md:hidden border-t border-border bg-background/95 backdrop-blur-md px-6 py-4 space-y-1 animate-fade-in">
            {NAV_LINKS.map((l) => (
              <a
                key={l.label}
                href={l.href}
                className="block py-2 text-sm text-muted hover:text-foreground transition-colors"
                onClick={() => setMobileOpen(false)}
              >
                {l.label}
              </a>
            ))}
            <div className="pt-3 flex flex-col gap-2 border-t border-border mt-3">
              <Link href="/dashboard" onClick={() => setMobileOpen(false)}>
                <Button variant="outline" size="sm" className="w-full">Sign In</Button>
              </Link>
              <Link href="/onboarding" onClick={() => setMobileOpen(false)}>
                <Button size="sm" className="w-full">Get Started</Button>
              </Link>
            </div>
          </div>
        )}
      </nav>

      {/* ── Hero ─────────────────────────────────────────────────────────── */}
      <section className="mx-auto max-w-6xl px-6 pt-24 pb-20 text-center">
        {/* Motto badge */}
        <div className="mb-4 inline-flex items-center gap-2 rounded-full border border-primary/30 bg-primary/5 px-4 py-1.5 text-xs font-medium text-primary">
          <FrostGateShield size={14} />
          Trust But Verify — the governing principle of AI governance
        </div>

        <h1 className="mt-6 text-4xl font-bold tracking-tight text-foreground sm:text-5xl lg:text-6xl">
          AI Governance for{' '}
          <span className="text-primary">Regulated Industries</span>
        </h1>

        <p className="mt-6 mx-auto max-w-2xl text-lg text-muted leading-relaxed">
          Your team is already using AI. FrostGate gives you the defensible governance
          framework to prove you took it seriously — before your regulator does.
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

        <p className="mt-4 text-xs text-muted">
          No credit card required · Results in 48 hours · 35–130 questions
        </p>
      </section>

      {/* ── Framework trust strip ─────────────────────────────────────────── */}
      <section className="border-y border-border bg-surface/50 py-5">
        <div className="mx-auto max-w-6xl px-6">
          <p className="text-center text-[11px] uppercase tracking-widest text-muted mb-4">
            Aligned with leading regulatory frameworks
          </p>
          <div className="flex flex-wrap items-center justify-center gap-x-6 gap-y-2">
            {FRAMEWORKS.map((fw) => (
              <span key={fw} className="text-xs text-muted/70 font-medium whitespace-nowrap">
                {fw}
              </span>
            ))}
          </div>
        </div>
      </section>

      {/* ── Risk callout ──────────────────────────────────────────────────── */}
      <section className="mx-auto max-w-6xl px-6 py-16">
        <div className="rounded-xl border border-danger/20 bg-danger/5 p-8 text-center">
          <AlertTriangle className="h-6 w-6 text-danger mx-auto mb-3" />
          <h2 className="text-xl font-semibold text-foreground mb-3">
            The average community bank scores{' '}
            <span className="text-danger">38/100</span> — High Risk
          </h2>
          <p className="text-muted text-sm max-w-xl mx-auto">
            Staff are using ChatGPT with customer NPI. No policy. No audit trail. No examiner
            answer. Regulators are asking now. FrostGate gives you a defensible answer in 48 hours.
          </p>
        </div>
      </section>

      {/* ── How It Works ─────────────────────────────────────────────────── */}
      <section id="how-it-works" className="bg-surface py-16">
        <div className="mx-auto max-w-6xl px-6">
          <div className="mb-12 text-center">
            <h2 className="text-2xl font-bold text-foreground">How it works</h2>
            <p className="mt-3 text-muted">
              From unknown exposure to defensible governance — in three steps.
            </p>
          </div>
          <div className="grid gap-6 sm:grid-cols-3">
            {HOW_IT_WORKS.map((s) => (
              <div key={s.step} className="relative flex flex-col items-start p-6 rounded-xl border border-border bg-surface-2">
                <div className={`flex h-10 w-10 items-center justify-center rounded-lg border ${s.bg} mb-4`}>
                  <s.icon className={`h-5 w-5 ${s.color}`} />
                </div>
                <span className="absolute top-4 right-5 text-4xl font-bold text-foreground/5 select-none">
                  {s.step}
                </span>
                <h3 className={`text-base font-semibold mb-2 ${s.color}`}>{s.title}</h3>
                <p className="text-sm text-muted leading-relaxed">{s.description}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ── Trust But Verify ─────────────────────────────────────────────── */}
      <section className="mx-auto max-w-6xl px-6 py-16">
        <div className="rounded-xl border border-border overflow-hidden">
          {/* Header */}
          <div className="bg-surface-2 px-8 py-6 text-center border-b border-border">
            <div className="flex items-center justify-center gap-3 mb-2">
              <FrostGateShield size={32} />
              <h2 className="text-xl font-bold text-foreground">Trust But Verify</h2>
            </div>
            <p className="text-sm text-muted max-w-xl mx-auto">
              Our motto isn&rsquo;t just a phrase — it&rsquo;s the architectural principle behind
              every layer of FrostGate.
            </p>
          </div>

          {/* Two columns */}
          <div className="grid sm:grid-cols-2 divide-y sm:divide-y-0 sm:divide-x divide-border">
            {/* Trust */}
            <div className="p-8 bg-info/5">
              <div className="flex items-center gap-2 mb-4">
                <div className="h-2 w-2 rounded-full bg-info" />
                <span className="text-xs font-semibold uppercase tracking-widest text-info">
                  Trust
                </span>
              </div>
              <h3 className="text-base font-semibold text-foreground mb-3">
                AI makes your organization more capable.
              </h3>
              <p className="text-sm text-muted leading-relaxed mb-4">
                We don&rsquo;t block AI — we give your team the foundation to use it with
                confidence. Community banks, medical groups, and law firms that embrace AI
                responsibly will outperform those that don&rsquo;t. FrostGate makes that possible.
              </p>
              <ul className="space-y-2">
                {[
                  'Enable AI adoption without governance paralysis',
                  'Profile-tuned assessment — not a one-size-fits-all checklist',
                  'Roadmap built for your actual risk tolerance',
                ].map((item) => (
                  <li key={item} className="flex items-start gap-2 text-xs text-muted">
                    <CheckCircle2 className="h-3.5 w-3.5 text-info shrink-0 mt-0.5" />
                    {item}
                  </li>
                ))}
              </ul>
            </div>

            {/* Verify */}
            <div className="p-8 bg-primary/5">
              <div className="flex items-center gap-2 mb-4">
                <div className="h-2 w-2 rounded-full bg-primary" />
                <span className="text-xs font-semibold uppercase tracking-widest text-primary">
                  Verify
                </span>
              </div>
              <h3 className="text-base font-semibold text-foreground mb-3">
                Every AI use must be auditable and defensible.
              </h3>
              <p className="text-sm text-muted leading-relaxed mb-4">
                Trust without verification isn&rsquo;t governance — it&rsquo;s exposure. We verify
                that every AI decision, every model call, every policy exception is logged,
                justified, and retrievable the moment a regulator or auditor asks.
              </p>
              <ul className="space-y-2">
                {[
                  'HMAC-chained audit log — tamper-evident by construction',
                  'OPA policy enforcement on every AI request',
                  'Framework alignment percentages your examiner can review',
                ].map((item) => (
                  <li key={item} className="flex items-start gap-2 text-xs text-muted">
                    <CheckCircle2 className="h-3.5 w-3.5 text-primary shrink-0 mt-0.5" />
                    {item}
                  </li>
                ))}
              </ul>
            </div>
          </div>
        </div>
      </section>

      {/* ── Features ─────────────────────────────────────────────────────── */}
      <section id="features" className="bg-surface py-16">
        <div className="mx-auto max-w-6xl px-6">
          <div className="mb-12 text-center">
            <h2 className="text-2xl font-bold text-foreground">Platform capabilities</h2>
            <p className="mt-3 text-muted">
              Four tiers. One platform. Assessment through runtime control.
            </p>
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
                  <CardDescription className="text-sm leading-relaxed">
                    {f.description}
                  </CardDescription>
                </CardContent>
              </Card>
            ))}
          </div>
        </div>
      </section>

      {/* ── Industries ───────────────────────────────────────────────────── */}
      <section id="industries" className="mx-auto max-w-6xl px-6 py-16">
        <div className="mb-10 text-center">
          <h2 className="text-2xl font-bold text-foreground">Built for regulated industries</h2>
          <p className="mt-3 text-muted">
            Compliance frameworks and scoring weights pre-tuned per vertical.
          </p>
        </div>
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          {INDUSTRIES.map((ind) => (
            <div
              key={ind.label}
              className="rounded-lg border border-border bg-surface p-5 hover:border-primary/30 transition-colors"
            >
              <ind.icon className="h-6 w-6 text-primary mb-3" />
              <p className="font-medium text-foreground text-sm">{ind.label}</p>
              <p className="mt-1 text-xs text-muted">{ind.note}</p>
            </div>
          ))}
        </div>
      </section>

      {/* ── Pricing ──────────────────────────────────────────────────────── */}
      <section id="pricing" className="bg-surface py-16">
        <div className="mx-auto max-w-6xl px-6">
          <div className="mb-12 text-center">
            <h2 className="text-2xl font-bold text-foreground">Simple, transparent pricing</h2>
            <p className="mt-3 text-muted">
              Start with a Snapshot. Scale to Control when you need it.
            </p>
          </div>
          <div className="grid gap-6 lg:grid-cols-4">
            {TIERS.map((tier) => (
              <div
                key={tier.name}
                className={`relative rounded-xl border p-6 flex flex-col ${
                  tier.badge === 'Most Popular'
                    ? 'border-primary bg-primary/5'
                    : 'border-border bg-surface-2'
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
        </div>
      </section>

      {/* ── Bottom CTA ───────────────────────────────────────────────────── */}
      <section className="mx-auto max-w-2xl px-6 py-16 text-center">
        <div className="flex items-center justify-center gap-3 mb-6">
          <FrostGateShield size={36} />
        </div>
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
        <p className="mt-3 text-xs text-muted">
          Trust your instincts. Verify with data.
        </p>
      </section>

      {/* ── Footer ───────────────────────────────────────────────────────── */}
      <footer className="border-t border-border py-10">
        <div className="mx-auto max-w-6xl px-6">
          <div className="flex flex-col items-center gap-6 sm:flex-row sm:justify-between sm:items-start">
            {/* Brand block */}
            <div className="flex flex-col items-center sm:items-start gap-1">
              <div className="flex items-center gap-2">
                <FrostGateShield size={22} />
                <span className="text-sm font-semibold text-foreground">FrostGate</span>
              </div>
              <p className="text-xs text-muted/70 tracking-widest uppercase">Trust But Verify</p>
              <p className="text-xs text-muted mt-1">
                &copy; {new Date().getFullYear()} FrostGate. Deltona, Florida.
              </p>
            </div>

            {/* Links */}
            <div className="flex gap-6 text-xs text-muted">
              <a href="#how-it-works" className="hover:text-foreground transition-colors">
                How It Works
              </a>
              <a href="#pricing" className="hover:text-foreground transition-colors">
                Pricing
              </a>
              <Link href="/dashboard" className="hover:text-foreground transition-colors">
                Sign In
              </Link>
              <a href="mailto:sales@frostgate.ai" className="hover:text-foreground transition-colors">
                Contact
              </a>
            </div>
          </div>

          {/* Framework disclaimer */}
          <div className="mt-8 pt-6 border-t border-border">
            <p className="text-[11px] text-muted/50 text-center leading-relaxed max-w-3xl mx-auto">
              FrostGate assessments and reports are designed to support alignment with, not
              certification to, NIST AI RMF, HIPAA, FFIEC CAT, CMMC 2.0, SOC 2, ISO/IEC
              27001:2022, and other referenced frameworks. No FrostGate deliverable constitutes
              legal advice, regulatory certification, or a guarantee of compliance.
            </p>
          </div>
        </div>
      </footer>
    </div>
  );
}
