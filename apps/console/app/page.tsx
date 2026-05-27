import type { Metadata } from 'next';
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
  XCircle,
  AlertTriangle,
  Building2,
  HeartPulse,
  Gavel,
  HardHat,
  ScanLine,
  ClipboardCheck,
  KeyRound,
  ShieldCheck,
  Database,
  Eye,
  Server,
  CalendarCheck,
} from 'lucide-react';
import { LandingNav } from '@/components/layout/LandingNav';
import { FrostGateShield } from '@/components/governance/FrostGateShield';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { ScrollReveal } from '@/components/landing/ScrollReveal';
import { StatStrip } from '@/components/landing/StatStrip';
import { FaqSection } from '@/components/landing/FaqSection';
import { StickyCtaBar } from '@/components/landing/StickyCtaBar';

// ─── Page SEO ─────────────────────────────────────────────────────────────────

export const metadata: Metadata = {
  title: 'FrostGate — Trust But Verify · AI Governance for Regulated Industries',
  description:
    'FrostGate is the AI governance platform for community banking, healthcare, legal, and defense. Get a defensible AI risk posture in 48 hours — starting at $299. Aligned with NIST AI RMF, HIPAA, FFIEC CAT, CMMC 2.0, and SOC 2.',
  alternates: { canonical: 'https://frostgate.ai/' },
  openGraph: {
    title: 'FrostGate — Trust But Verify · AI Governance for Regulated Industries',
    description:
      'The AI governance platform built for regulated industries. Assess, score, and verify your AI risk posture — starting at $299.',
    url: 'https://frostgate.ai/',
    type: 'website',
  },
};

// ─── JSON-LD ──────────────────────────────────────────────────────────────────

const jsonLd = {
  '@context': 'https://schema.org',
  '@graph': [
    {
      '@type': 'Organization',
      '@id': 'https://frostgate.ai/#organization',
      name: 'FrostGate',
      url: 'https://frostgate.ai',
      logo: { '@type': 'ImageObject', url: 'https://frostgate.ai/icon.svg', width: 32, height: 32 },
      description: 'AI governance platform for regulated industries — community banking, healthcare, legal, and defense.',
      slogan: 'Trust But Verify',
      address: { '@type': 'PostalAddress', addressLocality: 'Deltona', addressRegion: 'FL', addressCountry: 'US' },
      areaServed: [
        { '@type': 'State', name: 'Florida' },
        { '@type': 'AdministrativeArea', name: 'Volusia County, FL' },
        { '@type': 'AdministrativeArea', name: 'Flagler County, FL' },
        { '@type': 'AdministrativeArea', name: 'Orange County, FL' },
        { '@type': 'AdministrativeArea', name: 'Brevard County, FL' },
      ],
      contactPoint: { '@type': 'ContactPoint', email: 'sales@frostgate.ai', contactType: 'sales', availableLanguage: 'English' },
      knowsAbout: ['AI Governance', 'NIST AI Risk Management Framework', 'HIPAA', 'FFIEC CAT', 'CMMC 2.0', 'SOC 2'],
    },
    {
      '@type': 'WebSite',
      '@id': 'https://frostgate.ai/#website',
      url: 'https://frostgate.ai',
      name: 'FrostGate',
      publisher: { '@id': 'https://frostgate.ai/#organization' },
      inLanguage: 'en-US',
    },
    {
      '@type': 'SoftwareApplication',
      '@id': 'https://frostgate.ai/#app',
      name: 'FrostGate',
      applicationCategory: 'BusinessApplication',
      applicationSubCategory: 'Compliance & Risk Management',
      operatingSystem: 'Web',
      url: 'https://frostgate.ai',
      provider: { '@id': 'https://frostgate.ai/#organization' },
      description: 'AI governance assessment and advisory reporting platform for regulated industries.',
      offers: [
        { '@type': 'Offer', name: 'Snapshot', price: '299', priceCurrency: 'USD', priceSpecification: { '@type': 'UnitPriceSpecification', price: '299', priceCurrency: 'USD', priceType: 'https://schema.org/OneTimePurchase' }, url: 'https://frostgate.ai/onboarding' },
        { '@type': 'Offer', name: 'Intelligence', price: '5000', priceCurrency: 'USD', priceSpecification: { '@type': 'UnitPriceSpecification', price: '5000', priceCurrency: 'USD', billingDuration: 'P1Y', priceType: 'https://schema.org/RecurringCharge' } },
      ],
    },
    {
      '@type': 'WebPage',
      '@id': 'https://frostgate.ai/#webpage',
      url: 'https://frostgate.ai',
      name: 'FrostGate — Trust But Verify · AI Governance for Regulated Industries',
      isPartOf: { '@id': 'https://frostgate.ai/#website' },
      about: { '@id': 'https://frostgate.ai/#app' },
      publisher: { '@id': 'https://frostgate.ai/#organization' },
      inLanguage: 'en-US',
      breadcrumb: { '@type': 'BreadcrumbList', itemListElement: [{ '@type': 'ListItem', position: 1, name: 'Home', item: 'https://frostgate.ai/' }] },
    },
  ],
};

// ─── Data ─────────────────────────────────────────────────────────────────────

const FRAMEWORKS = ['NIST AI RMF', 'HIPAA + HHS OCR', 'FFIEC CAT', 'CMMC 2.0', 'SOC 2 Type II', 'ISO 27001', 'NIST 800-171', 'DFARS'];

const HOW_IT_WORKS = [
  { step: '01', icon: ScanLine, title: 'Assess', color: 'text-info', bg: 'bg-info/10 border-info/20', description: 'Complete a profile-tuned questionnaire — 35 to 130 questions calibrated to your industry, size, and regulatory exposure. No generic checklists.' },
  { step: '02', icon: BarChart3, title: 'Score', color: 'text-warning', bg: 'bg-warning/10 border-warning/20', description: 'Receive a risk score across 6 governance domains — data governance, security posture, AI maturity, infra readiness, compliance awareness, and automation potential.' },
  { step: '03', icon: ClipboardCheck, title: 'Verify', color: 'text-primary', bg: 'bg-primary/10 border-primary/20', description: 'Get a Claude-powered advisory report with a 30/60/90-day roadmap and framework alignment percentages — a defensible answer for when your regulator asks.' },
];

const SECURITY_ITEMS = [
  { icon: Database, title: 'Tenant data isolation', body: 'Every database query is scoped to your tenant via Row Level Security. No query can access another organization\'s data — by construction, not by convention.' },
  { icon: Shield, title: 'HMAC-chained audit log', body: 'Our audit log is append-only and HMAC-chained — each record cryptographically references the one before it. Tampering with any record breaks the chain and is immediately detectable.' },
  { icon: Lock, title: 'Encryption in transit', body: 'All traffic between your browser and our API is encrypted with TLS 1.3. Connections that do not meet this standard are rejected.' },
  { icon: Eye, title: 'Zero AI training use', body: 'Your assessment responses and generated reports are never used to train any AI model — including the Claude model used for report generation. Your data is used solely to produce your deliverable.' },
  { icon: KeyRound, title: 'API key authentication', body: 'Platform access uses scoped API keys with per-scope permissions (read, write, admin). Keys are hashed with Argon2 — raw values are never stored.' },
  { icon: Server, title: 'OPA policy enforcement', body: 'All AI requests through the Control tier are evaluated by an Open Policy Agent (Rego) policy engine before reaching any model. Decisions are logged and auditable.' },
  { icon: ShieldCheck, title: 'BAA available', body: 'Healthcare organizations that handle PHI can execute a Business Associate Agreement with us before starting their assessment. Contact us before purchasing.' },
  { icon: CalendarCheck, title: 'SOC 2 Type II roadmap', body: 'We are building toward SOC 2 Type II certification. Audit controls are designed to meet Trust Service Criteria for security, availability, and confidentiality. We will publish the report when complete.' },
];

const VS_ROWS = [
  { feature: 'Questions tuned to your industry & size', fg: true, generic: false },
  { feature: 'Profile classification before assessment starts', fg: true, generic: false },
  { feature: 'AI-generated advisory report', fg: true, generic: false },
  { feature: '30/60/90-day remediation roadmap', fg: true, generic: false },
  { feature: 'Framework alignment percentages', fg: true, generic: false },
  { feature: 'HMAC-chained tamper-evident audit log', fg: true, generic: false },
  { feature: 'Banking-specific FFIEC CAT weighting', fg: true, generic: false },
  { feature: 'Healthcare HIPAA + HHS OCR AI guidance', fg: true, generic: false },
  { feature: 'CMMC 2.0 / NIST 800-171 for GovCon', fg: true, generic: false },
  { feature: 'Central Florida–based team', fg: true, generic: false },
  { feature: 'Generic NIST/ISO checklist', fg: false, generic: true },
];

const COMPARE_FEATURES = [
  { section: 'Core — all plans', rows: [
    { name: 'AI governance assessment', snap: true, intel: true, ctrl: true, auto: true },
    { name: 'Risk scoring across 6 domains', snap: true, intel: true, ctrl: true, auto: true },
    { name: 'AI advisory report (executive)', snap: true, intel: true, ctrl: true, auto: true },
    { name: '30/60/90-day remediation roadmap', snap: true, intel: true, ctrl: true, auto: true },
    { name: 'Compliance framework alignment', snap: true, intel: true, ctrl: true, auto: true },
    { name: 'Shareable report link', snap: true, intel: true, ctrl: true, auto: true },
  ]},
  { section: 'Intelligence +', rows: [
    { name: 'Live compliance dashboard', snap: false, intel: true, ctrl: true, auto: true },
    { name: 'Industry benchmarking (anonymized)', snap: false, intel: true, ctrl: true, auto: true },
    { name: 'RAG-grounded policy recommendations', snap: false, intel: true, ctrl: true, auto: true },
    { name: 'Multi-user RBAC (exec/auditor/admin)', snap: false, intel: true, ctrl: true, auto: true },
    { name: 'Risk score trend tracking', snap: false, intel: true, ctrl: true, auto: true },
    { name: 'Assessment delegation by department', snap: false, intel: true, ctrl: true, auto: true },
  ]},
  { section: 'Control +', rows: [
    { name: 'Drop-in AI gateway (Anthropic/OpenAI proxy)', snap: false, intel: false, ctrl: true, auto: true },
    { name: 'Real-time OPA policy enforcement', snap: false, intel: false, ctrl: true, auto: true },
    { name: 'PII/PHI/CUI tokenization at AI boundary', snap: false, intel: false, ctrl: true, auto: true },
    { name: 'Provider routing by data classification', snap: false, intel: false, ctrl: true, auto: true },
    { name: 'Forensic HMAC audit log (customer-facing)', snap: false, intel: false, ctrl: true, auto: true },
  ]},
  { section: 'Autonomous', rows: [
    { name: 'Continuous risk monitoring', snap: false, intel: false, ctrl: false, auto: true },
    { name: 'Configuration drift detection', snap: false, intel: false, ctrl: false, auto: true },
    { name: 'Auto-remediation suggestions', snap: false, intel: false, ctrl: false, auto: true },
    { name: 'Predictive risk modeling', snap: false, intel: false, ctrl: false, auto: true },
    { name: 'Custom compliance modules', snap: false, intel: false, ctrl: false, auto: true },
    { name: 'Dedicated customer success manager', snap: false, intel: false, ctrl: false, auto: true },
  ]},
];

const TIERS = [
  { name: 'Snapshot', price: '$299', period: 'one-time', badge: null as string | null, cta: 'Start Assessment', href: '/onboarding', features: ['AI governance assessment (35–130 questions)', 'Risk scoring across 6 domains', 'AI-generated executive report', '30/60/90 day remediation roadmap', 'Compliance framework alignment', 'Shareable report link'] },
  { name: 'Intelligence', price: '$5,000', period: 'per year', badge: 'Most Popular' as string | null, cta: 'Get Intelligence', href: '/onboarding?tier=intelligence', features: ['Everything in Snapshot', 'Live compliance dashboard', 'Industry benchmarking', 'Policy-grounded RAG recommendations', 'Multi-user RBAC (exec/auditor/admin)', 'Assessment delegation'] },
  { name: 'Control', price: '$50,000', period: 'per year', badge: 'Enterprise' as string | null, cta: 'Book a Call', href: 'mailto:sales@frostgate.ai?subject=FrostGate Control tier inquiry', features: ['Everything in Intelligence', 'Drop-in Anthropic/OpenAI proxy', 'Real-time OPA policy enforcement', 'PII/PHI/CUI tokenization at AI boundary', 'Provider routing by classification', 'HMAC-chained forensic audit log'] },
  { name: 'Autonomous', price: '$100,000', period: 'per year', badge: null as string | null, cta: 'Book a Call', href: 'mailto:sales@frostgate.ai?subject=FrostGate Autonomous tier inquiry', features: ['Everything in Control', 'Continuous risk monitoring', 'Drift detection + alerting', 'Auto-remediation suggestions', 'Predictive risk modeling', 'Custom compliance modules'] },
];

const INDUSTRIES = [
  { icon: Building2, label: 'Community Banking', note: 'FFIEC CAT · SR 11-7 · GLBA' },
  { icon: HeartPulse, label: 'Healthcare', note: 'HIPAA · HITRUST · HHS OCR' },
  { icon: Gavel, label: 'Legal', note: 'Florida Bar 4-1.6 · ABA 512' },
  { icon: HardHat, label: 'Defense Contractors', note: 'CMMC 2.0 · NIST 800-171 · DFARS' },
];

const FEATURES = [
  { icon: Shield, title: 'Policy-Aware Assessment', description: 'Profile-driven questionnaires that match your org size, industry, and regulatory exposure. No generic checklists.' },
  { icon: BrainCircuit, title: 'AI-Generated Reports', description: 'Claude-powered advisory reports in executive, technical, and compliance variants — always with a 30/60/90 day roadmap.' },
  { icon: Lock, title: 'Runtime Gateway', description: 'Drop-in proxy that classifies every AI request, enforces OPA policies, tokenizes PII/PHI, and logs with HMAC-chain integrity.' },
  { icon: BarChart3, title: 'Compliance Mapping', description: 'Automatic alignment scoring across NIST AI RMF, SOC 2, HIPAA, FFIEC CAT, CMMC 2.0, and 10+ other frameworks.' },
  { icon: FileCheck, title: 'Forensic Audit Log', description: 'Append-only, HMAC-chained audit trail. Tamper-evident by construction — holds up in examiner review.' },
  { icon: Users, title: 'Multi-Tenant RBAC', description: 'Role-scoped access for exec, auditor, admin, operator, and viewer. Built for regulated environments with audit delegation.' },
];

function Check() {
  return <CheckCircle2 className="h-4 w-4 text-success mx-auto" aria-label="Included" />;
}
function Dash() {
  return <span className="text-muted text-sm mx-auto block text-center" aria-label="Not included">—</span>;
}

// ─── Page ─────────────────────────────────────────────────────────────────────

export default function LandingPage() {
  return (
    <>
      <script
        type="application/ld+json"
        suppressHydrationWarning
        dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd) }}
      />

      <div className="min-h-screen bg-background text-foreground">
        <LandingNav />

        {/* ── Hero ─────────────────────────────────────────────────────────── */}
        <section className="relative mx-auto max-w-6xl px-6 pt-24 pb-20 text-center overflow-hidden">
          {/* Ambient glow — purely decorative */}
          <div aria-hidden className="pointer-events-none absolute inset-0 -z-10">
            <div
              className="hero-glow absolute"
              style={{ left: '50%', top: '30%', width: 640, height: 640, transform: 'translate(-50%,-50%)', background: 'radial-gradient(circle, rgba(255,90,31,0.07) 0%, transparent 70%)' }}
            />
            <div
              className="hero-glow absolute"
              style={{ left: '30%', top: '60%', width: 420, height: 420, transform: 'translate(-50%,-50%)', background: 'radial-gradient(circle, rgba(59,130,246,0.05) 0%, transparent 70%)' }}
            />
          </div>

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
                <span key={fw} className="text-xs text-muted/70 font-medium whitespace-nowrap">{fw}</span>
              ))}
            </div>
          </div>
        </section>

        {/* ── Stats ────────────────────────────────────────────────────────── */}
        <section className="mx-auto max-w-6xl px-6 py-16">
          <ScrollReveal>
            <StatStrip />
          </ScrollReveal>
        </section>

        {/* ── Risk callout ──────────────────────────────────────────────────── */}
        <ScrollReveal className="mx-auto max-w-6xl px-6 pb-16">
          <div className="rounded-xl border border-danger/20 bg-danger/5 p-8 text-center">
            <AlertTriangle className="h-6 w-6 text-danger mx-auto mb-3" />
            <h2 className="text-xl font-semibold text-foreground mb-3">
              The average community bank scores <span className="text-danger">38/100</span> — High Risk
            </h2>
            <p className="text-muted text-sm max-w-xl mx-auto">
              Staff are using ChatGPT with customer NPI. No policy. No audit trail. No examiner
              answer. Regulators are asking now. FrostGate gives you a defensible answer in 48 hours.
            </p>
          </div>
        </ScrollReveal>

        {/* ── How It Works ─────────────────────────────────────────────────── */}
        <section id="how-it-works" className="bg-surface py-16">
          <div className="mx-auto max-w-6xl px-6">
            <ScrollReveal>
              <div className="mb-12 text-center">
                <h2 className="text-2xl font-bold text-foreground">How it works</h2>
                <p className="mt-3 text-muted">From unknown exposure to defensible governance — in three steps.</p>
              </div>
            </ScrollReveal>
            <div className="grid gap-6 sm:grid-cols-3">
              {HOW_IT_WORKS.map((s, i) => (
                <ScrollReveal key={s.step} delay={i * 120}>
                  <div className="relative flex flex-col items-start p-6 rounded-xl border border-border bg-surface-2 h-full">
                    <div className={`flex h-10 w-10 items-center justify-center rounded-lg border ${s.bg} mb-4`}>
                      <s.icon className={`h-5 w-5 ${s.color}`} />
                    </div>
                    <span className="absolute top-4 right-5 text-4xl font-bold text-foreground/5 select-none">{s.step}</span>
                    <h3 className={`text-base font-semibold mb-2 ${s.color}`}>{s.title}</h3>
                    <p className="text-sm text-muted leading-relaxed">{s.description}</p>
                  </div>
                </ScrollReveal>
              ))}
            </div>
          </div>
        </section>

        {/* ── Trust But Verify ─────────────────────────────────────────────── */}
        <section className="mx-auto max-w-6xl px-6 py-16">
          <ScrollReveal>
            <div className="rounded-xl border border-border overflow-hidden">
              <div className="bg-surface-2 px-8 py-6 text-center border-b border-border">
                <div className="flex items-center justify-center gap-3 mb-2">
                  <FrostGateShield size={32} />
                  <h2 className="text-xl font-bold text-foreground">Trust But Verify</h2>
                </div>
                <p className="text-sm text-muted max-w-xl mx-auto">
                  Our motto isn&rsquo;t just a phrase — it&rsquo;s the architectural principle behind every layer of FrostGate.
                </p>
              </div>
              <div className="grid sm:grid-cols-2 divide-y sm:divide-y-0 sm:divide-x divide-border">
                <div className="p-8 bg-info/5">
                  <div className="flex items-center gap-2 mb-4">
                    <div className="h-2 w-2 rounded-full bg-info" />
                    <span className="text-xs font-semibold uppercase tracking-widest text-info">Trust</span>
                  </div>
                  <h3 className="text-base font-semibold text-foreground mb-3">AI makes your organization more capable.</h3>
                  <p className="text-sm text-muted leading-relaxed mb-4">
                    We don&rsquo;t block AI — we give your team the foundation to use it with confidence. Community banks, medical groups, and law firms that embrace AI responsibly will outperform those that don&rsquo;t. FrostGate makes that possible.
                  </p>
                  <ul className="space-y-2">
                    {['Enable AI adoption without governance paralysis', 'Profile-tuned assessment — not a one-size-fits-all checklist', 'Roadmap built for your actual risk tolerance'].map((item) => (
                      <li key={item} className="flex items-start gap-2 text-xs text-muted">
                        <CheckCircle2 className="h-3.5 w-3.5 text-info shrink-0 mt-0.5" />{item}
                      </li>
                    ))}
                  </ul>
                </div>
                <div className="p-8 bg-primary/5">
                  <div className="flex items-center gap-2 mb-4">
                    <div className="h-2 w-2 rounded-full bg-primary" />
                    <span className="text-xs font-semibold uppercase tracking-widest text-primary">Verify</span>
                  </div>
                  <h3 className="text-base font-semibold text-foreground mb-3">Every AI use must be auditable and defensible.</h3>
                  <p className="text-sm text-muted leading-relaxed mb-4">
                    Trust without verification isn&rsquo;t governance — it&rsquo;s exposure. We verify that every AI decision, every model call, every policy exception is logged, justified, and retrievable the moment a regulator or auditor asks.
                  </p>
                  <ul className="space-y-2">
                    {['HMAC-chained audit log — tamper-evident by construction', 'OPA policy enforcement on every AI request', 'Framework alignment percentages your examiner can review'].map((item) => (
                      <li key={item} className="flex items-start gap-2 text-xs text-muted">
                        <CheckCircle2 className="h-3.5 w-3.5 text-primary shrink-0 mt-0.5" />{item}
                      </li>
                    ))}
                  </ul>
                </div>
              </div>
            </div>
          </ScrollReveal>
        </section>

        {/* ── Security ─────────────────────────────────────────────────────── */}
        <section id="security" className="bg-surface py-16">
          <div className="mx-auto max-w-6xl px-6">
            <ScrollReveal>
              <div className="mb-12 text-center">
                <h2 className="text-2xl font-bold text-foreground">Built for regulated security requirements</h2>
                <p className="mt-3 text-muted max-w-2xl mx-auto">
                  Enterprise procurement asks hard questions. Here are direct answers — each backed by implemented architecture, not marketing language.
                </p>
              </div>
            </ScrollReveal>
            <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
              {SECURITY_ITEMS.map((item, i) => (
                <ScrollReveal key={item.title} delay={i * 60}>
                  <div className="h-full rounded-lg border border-border bg-surface-2 p-5">
                    <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-primary/10 mb-3">
                      <item.icon className="h-4 w-4 text-primary" />
                    </div>
                    <p className="text-sm font-semibold text-foreground mb-1.5">{item.title}</p>
                    <p className="text-xs text-muted leading-relaxed">{item.body}</p>
                  </div>
                </ScrollReveal>
              ))}
            </div>
          </div>
        </section>

        {/* ── Why FrostGate ─────────────────────────────────────────────────── */}
        <section className="mx-auto max-w-6xl px-6 py-16">
          <ScrollReveal>
            <div className="mb-12 text-center">
              <h2 className="text-2xl font-bold text-foreground">Why not a generic compliance template?</h2>
              <p className="mt-3 text-muted">FrostGate vs. a standard checklist tool — a straight comparison.</p>
            </div>
          </ScrollReveal>
          <ScrollReveal>
            <div className="rounded-xl border border-border overflow-hidden">
              {/* Header */}
              <div className="grid grid-cols-3 bg-surface-2 border-b border-border">
                <div className="px-5 py-3 text-xs font-semibold text-muted uppercase tracking-wider">Capability</div>
                <div className="px-5 py-3 text-xs font-semibold text-foreground uppercase tracking-wider border-x border-border flex items-center gap-2">
                  <FrostGateShield size={14} /> FrostGate
                </div>
                <div className="px-5 py-3 text-xs font-semibold text-muted uppercase tracking-wider">Generic checklist</div>
              </div>
              {VS_ROWS.map((row, i) => (
                <div
                  key={row.feature}
                  className={`grid grid-cols-3 border-b border-border last:border-0 ${i % 2 === 0 ? 'bg-surface' : 'bg-surface-2'}`}
                >
                  <div className="px-5 py-3 text-sm text-foreground">{row.feature}</div>
                  <div className="px-5 py-3 border-x border-border flex items-center justify-center">
                    {row.fg ? <CheckCircle2 className="h-4 w-4 text-success" /> : <XCircle className="h-4 w-4 text-muted/40" />}
                  </div>
                  <div className="px-5 py-3 flex items-center justify-center">
                    {row.generic ? <CheckCircle2 className="h-4 w-4 text-success" /> : <XCircle className="h-4 w-4 text-muted/40" />}
                  </div>
                </div>
              ))}
            </div>
          </ScrollReveal>
        </section>

        {/* ── Features ─────────────────────────────────────────────────────── */}
        <section id="features" className="bg-surface py-16">
          <div className="mx-auto max-w-6xl px-6">
            <ScrollReveal>
              <div className="mb-12 text-center">
                <h2 className="text-2xl font-bold text-foreground">Platform capabilities</h2>
                <p className="mt-3 text-muted">Four tiers. One platform. Assessment through runtime control.</p>
              </div>
            </ScrollReveal>
            <div className="grid gap-6 sm:grid-cols-2 lg:grid-cols-3">
              {FEATURES.map((f, i) => (
                <ScrollReveal key={f.title} delay={i * 80}>
                  <Card className="hover:border-primary/30 transition-colors h-full">
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
                </ScrollReveal>
              ))}
            </div>
          </div>
        </section>

        {/* ── Industries ───────────────────────────────────────────────────── */}
        <section id="industries" className="mx-auto max-w-6xl px-6 py-16">
          <ScrollReveal>
            <div className="mb-10 text-center">
              <h2 className="text-2xl font-bold text-foreground">Built for regulated industries</h2>
              <p className="mt-3 text-muted">Compliance frameworks and scoring weights pre-tuned per vertical.</p>
            </div>
          </ScrollReveal>
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
            {INDUSTRIES.map((ind, i) => (
              <ScrollReveal key={ind.label} delay={i * 80}>
                <div className="rounded-lg border border-border bg-surface p-5 hover:border-primary/30 transition-colors">
                  <ind.icon className="h-6 w-6 text-primary mb-3" />
                  <p className="font-medium text-foreground text-sm">{ind.label}</p>
                  <p className="mt-1 text-xs text-muted">{ind.note}</p>
                </div>
              </ScrollReveal>
            ))}
          </div>
        </section>

        {/* ── Pricing ──────────────────────────────────────────────────────── */}
        <section id="pricing" className="bg-surface py-16">
          <div className="mx-auto max-w-6xl px-6">
            <ScrollReveal>
              <div className="mb-12 text-center">
                <h2 className="text-2xl font-bold text-foreground">Simple, transparent pricing</h2>
                <p className="mt-3 text-muted">Start with a Snapshot. Scale to Control when you need it.</p>
              </div>
            </ScrollReveal>
            <div className="grid gap-6 lg:grid-cols-4">
              {TIERS.map((tier, i) => (
                <ScrollReveal key={tier.name} delay={i * 80}>
                  <div className={`relative rounded-xl border p-6 flex flex-col h-full ${tier.badge === 'Most Popular' ? 'border-primary bg-primary/5' : 'border-border bg-surface-2'}`}>
                    {tier.badge && (
                      <Badge variant={tier.badge === 'Most Popular' ? 'default' : 'secondary'} className="absolute -top-3 left-1/2 -translate-x-1/2">
                        {tier.badge}
                      </Badge>
                    )}
                    <div className="mb-4">
                      <p className="text-sm font-medium text-muted">{tier.name}</p>
                      <div className="mt-1 flex items-baseline gap-1">
                        <span className="text-2xl font-bold text-foreground">{tier.price}</span>
                        <span className="text-xs text-muted">{tier.period}</span>
                      </div>
                    </div>
                    <ul className="flex-1 space-y-2 mb-6">
                      {tier.features.map((f) => (
                        <li key={f} className="flex items-start gap-2 text-xs text-foreground">
                          <CheckCircle2 className="h-3.5 w-3.5 text-primary shrink-0 mt-0.5" />{f}
                        </li>
                      ))}
                    </ul>
                    <Link href={tier.href}>
                      <Button variant={tier.badge === 'Most Popular' ? 'default' : 'outline'} className="w-full" size="sm">
                        {tier.cta}
                      </Button>
                    </Link>
                  </div>
                </ScrollReveal>
              ))}
            </div>
          </div>
        </section>

        {/* ── Comparison table ─────────────────────────────────────────────── */}
        <section className="mx-auto max-w-6xl px-6 py-16">
          <ScrollReveal>
            <div className="mb-10 text-center">
              <h2 className="text-2xl font-bold text-foreground">Full feature comparison</h2>
              <p className="mt-3 text-muted">Every capability, by tier.</p>
            </div>
          </ScrollReveal>
          <ScrollReveal>
            <div className="overflow-x-auto rounded-xl border border-border">
              <table className="w-full min-w-[640px] text-sm">
                <thead>
                  <tr className="border-b border-border bg-surface-2">
                    <th className="px-4 py-3 text-left text-xs font-semibold text-muted uppercase tracking-wider w-[40%]">Feature</th>
                    <th className="px-4 py-3 text-center text-xs font-semibold text-muted uppercase tracking-wider">Snapshot</th>
                    <th className="px-4 py-3 text-center text-xs font-semibold text-primary uppercase tracking-wider bg-primary/5 border-x border-primary/20">Intelligence</th>
                    <th className="px-4 py-3 text-center text-xs font-semibold text-muted uppercase tracking-wider">Control</th>
                    <th className="px-4 py-3 text-center text-xs font-semibold text-muted uppercase tracking-wider">Autonomous</th>
                  </tr>
                </thead>
                <tbody>
                  {COMPARE_FEATURES.map((group) => (
                    <>
                      <tr key={group.section} className="border-b border-border bg-surface-3">
                        <td colSpan={5} className="px-4 py-2 text-[11px] font-semibold uppercase tracking-widest text-muted">{group.section}</td>
                      </tr>
                      {group.rows.map((row, i) => (
                        <tr key={row.name} className={`border-b border-border last:border-0 ${i % 2 === 0 ? 'bg-surface' : 'bg-surface-2'}`}>
                          <td className="px-4 py-3 text-sm text-foreground">{row.name}</td>
                          <td className="px-4 py-3 text-center">{row.snap ? <Check /> : <Dash />}</td>
                          <td className="px-4 py-3 text-center bg-primary/5 border-x border-primary/20">{row.intel ? <Check /> : <Dash />}</td>
                          <td className="px-4 py-3 text-center">{row.ctrl ? <Check /> : <Dash />}</td>
                          <td className="px-4 py-3 text-center">{row.auto ? <Check /> : <Dash />}</td>
                        </tr>
                      ))}
                    </>
                  ))}
                </tbody>
              </table>
            </div>
          </ScrollReveal>
        </section>

        {/* ── FAQ ──────────────────────────────────────────────────────────── */}
        <section id="faq" className="bg-surface py-16">
          <div className="mx-auto max-w-3xl px-6">
            <ScrollReveal>
              <div className="mb-10 text-center">
                <h2 className="text-2xl font-bold text-foreground">Frequently asked questions</h2>
                <p className="mt-3 text-muted">Direct answers to the questions enterprise buyers ask most.</p>
              </div>
            </ScrollReveal>
            <ScrollReveal>
              <FaqSection />
            </ScrollReveal>
          </div>
        </section>

        {/* ── Bottom CTA ───────────────────────────────────────────────────── */}
        <section className="mx-auto max-w-2xl px-6 py-16 text-center">
          <div className="flex items-center justify-center gap-3 mb-6">
            <FrostGateShield size={36} />
          </div>
          <h2 className="text-2xl font-bold text-foreground">Your regulators are already asking about AI governance.</h2>
          <p className="mt-4 text-muted">
            Get a defensible risk posture in 48 hours — starting at $299. No enterprise contract required to know where you stand.
          </p>
          <div className="mt-8 flex flex-col items-center gap-3 sm:flex-row sm:justify-center">
            <Link href="/onboarding">
              <Button size="lg" className="gap-2">Start Your Assessment <ArrowRight className="h-4 w-4" /></Button>
            </Link>
            <a href="mailto:sales@frostgate.ai?subject=FrostGate demo request">
              <Button variant="outline" size="lg">Book a Demo</Button>
            </a>
          </div>
          <p className="mt-3 text-xs text-muted">Trust your instincts. Verify with data.</p>
        </section>

        {/* ── Footer ───────────────────────────────────────────────────────── */}
        <footer className="border-t border-border py-10">
          <div className="mx-auto max-w-6xl px-6">
            <div className="flex flex-col items-center gap-6 sm:flex-row sm:justify-between sm:items-start">
              <div className="flex flex-col items-center sm:items-start gap-1">
                <div className="flex items-center gap-2">
                  <FrostGateShield size={22} />
                  <span className="text-sm font-semibold text-foreground">FrostGate</span>
                </div>
                <p className="text-xs text-muted/70 tracking-widest uppercase">Trust But Verify</p>
                <p className="text-xs text-muted mt-1">&copy; {new Date().getFullYear()} FrostGate. Deltona, Florida.</p>
              </div>
              <div className="flex flex-wrap justify-center gap-x-6 gap-y-2 text-xs text-muted">
                <a href="#how-it-works" className="hover:text-foreground transition-colors">How It Works</a>
                <a href="#security" className="hover:text-foreground transition-colors">Security</a>
                <a href="#pricing" className="hover:text-foreground transition-colors">Pricing</a>
                <a href="#faq" className="hover:text-foreground transition-colors">FAQ</a>
                <Link href="/dashboard" className="hover:text-foreground transition-colors">Sign In</Link>
                <a href="mailto:sales@frostgate.ai" className="hover:text-foreground transition-colors">Contact</a>
              </div>
            </div>
            <div className="mt-8 pt-6 border-t border-border">
              <p className="text-[11px] text-muted/50 text-center leading-relaxed max-w-3xl mx-auto">
                FrostGate assessments and reports are designed to support alignment with, not certification to, NIST AI RMF, HIPAA, FFIEC CAT, CMMC 2.0, SOC 2, ISO/IEC 27001:2022, and other referenced frameworks. No FrostGate deliverable constitutes legal advice, regulatory certification, or a guarantee of compliance. SOC 2 Type II certification is in progress — the platform is not currently certified.
              </p>
            </div>
          </div>
        </footer>

        {/* Mobile sticky CTA — appears after hero scroll */}
        <StickyCtaBar />
      </div>
    </>
  );
}
