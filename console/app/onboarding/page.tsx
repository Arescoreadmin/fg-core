'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import {
  ArrowRight,
  ArrowLeft,
  Zap,
  Building2,
  Users,
  DollarSign,
  Shield,
  CreditCard,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Checkbox } from '@/components/ui/checkbox';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { Progress } from '@/components/ui/progress';
import { useOnboardingStore } from '@/lib/store';
import { assessmentApi } from '@/lib/assessmentApi';

// ─── Schemas ────────────────────────────────────────────────────────────────

const step0Schema = z.object({
  orgName: z.string().min(2, 'Organization name is required'),
  email: z.string().email('A valid email is required'),
  industry: z.string().min(1, 'Please select an industry'),
});

const step1Schema = z.object({
  employeeCount: z.string().min(1, 'Please select employee count'),
  revenue: z.string().min(1, 'Please select annual revenue'),
});

type Step0Data = z.infer<typeof step0Schema>;
type Step1Data = z.infer<typeof step1Schema>;

// ─── Tier pricing helper ─────────────────────────────────────────────────────

function tierPrice(data: { isDodContractor: boolean; handlesCui: boolean; handlesPhi: boolean; industry: string; employeeCount: string }) {
  if (data.isDodContractor || data.handlesCui) return '$999';
  if (data.handlesPhi || data.industry === 'banking' || data.industry === 'healthcare') return '$999';
  const n = parseInt(data.employeeCount?.split('-')[0] ?? '0', 10);
  if (n > 200) return '$599';
  if (n > 50) return '$599';
  return '$299';
}

// ─── Step components ─────────────────────────────────────────────────────────

function Step0({ onNext }: { onNext: () => void }) {
  const { data, setData } = useOnboardingStore();
  const {
    register,
    handleSubmit,
    setValue,
    formState: { errors },
  } = useForm<Step0Data>({
    resolver: zodResolver(step0Schema),
    defaultValues: { orgName: data.orgName, email: data.email, industry: data.industry },
  });

  const onSubmit = (values: Step0Data) => {
    setData(values as Parameters<typeof setData>[0]);
    onNext();
  };

  return (
    <form onSubmit={handleSubmit(onSubmit)} className="space-y-5">
      <div className="space-y-2">
        <Label htmlFor="orgName">Organization name</Label>
        <Input id="orgName" placeholder="Acme Community Bank" {...register('orgName')} />
        {errors.orgName && <p className="text-xs text-danger">{errors.orgName.message}</p>}
      </div>

      <div className="space-y-2">
        <Label htmlFor="email">Work email</Label>
        <Input id="email" type="email" placeholder="you@company.com" {...register('email')} />
        {errors.email && <p className="text-xs text-danger">{errors.email.message}</p>}
      </div>

      <div className="space-y-2">
        <Label>Industry</Label>
        <Select
          defaultValue={data.industry}
          onValueChange={(v) => {
            setValue('industry', v);
            setData({ industry: v as Parameters<typeof setData>[0]['industry'] });
          }}
        >
          <SelectTrigger>
            <SelectValue placeholder="Select industry…" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="banking">Community Banking / Credit Union</SelectItem>
            <SelectItem value="healthcare">Healthcare / Medical Group</SelectItem>
            <SelectItem value="legal">Legal / Law Firm</SelectItem>
            <SelectItem value="defense">Defense / Government Contracting</SelectItem>
            <SelectItem value="technology">Technology</SelectItem>
            <SelectItem value="insurance">Insurance</SelectItem>
            <SelectItem value="other">Other</SelectItem>
          </SelectContent>
        </Select>
        {errors.industry && <p className="text-xs text-danger">{errors.industry.message}</p>}
      </div>

      <Button type="submit" className="w-full gap-2">
        Continue <ArrowRight className="h-4 w-4" />
      </Button>
    </form>
  );
}

function Step1({ onNext, onBack }: { onNext: () => void; onBack: () => void }) {
  const { data, setData } = useOnboardingStore();
  const {
    handleSubmit,
    setValue,
    formState: { errors },
  } = useForm<Step1Data>({
    resolver: zodResolver(step1Schema),
    defaultValues: { employeeCount: data.employeeCount, revenue: data.revenue },
  });

  const onSubmit = (values: Step1Data) => {
    setData(values);
    onNext();
  };

  return (
    <form onSubmit={handleSubmit(onSubmit)} className="space-y-5">
      <div className="space-y-2">
        <Label>Employee count</Label>
        <Select
          defaultValue={data.employeeCount}
          onValueChange={(v) => {
            setValue('employeeCount', v);
            setData({ employeeCount: v });
          }}
        >
          <SelectTrigger>
            <SelectValue placeholder="Select range…" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="1-10">1–10 employees</SelectItem>
            <SelectItem value="11-50">11–50 employees</SelectItem>
            <SelectItem value="51-200">51–200 employees</SelectItem>
            <SelectItem value="201-500">201–500 employees</SelectItem>
            <SelectItem value="501-1000">501–1,000 employees</SelectItem>
            <SelectItem value="1001+">1,000+ employees</SelectItem>
          </SelectContent>
        </Select>
        {errors.employeeCount && <p className="text-xs text-danger">{errors.employeeCount.message}</p>}
      </div>

      <div className="space-y-2">
        <Label>Annual revenue / assets under management</Label>
        <Select
          defaultValue={data.revenue}
          onValueChange={(v) => {
            setValue('revenue', v);
            setData({ revenue: v });
          }}
        >
          <SelectTrigger>
            <SelectValue placeholder="Select range…" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="under_1m">Under $1M</SelectItem>
            <SelectItem value="1m_10m">$1M–$10M</SelectItem>
            <SelectItem value="10m_50m">$10M–$50M</SelectItem>
            <SelectItem value="50m_250m">$50M–$250M</SelectItem>
            <SelectItem value="250m_1b">$250M–$1B</SelectItem>
            <SelectItem value="over_1b">Over $1B</SelectItem>
          </SelectContent>
        </Select>
        {errors.revenue && <p className="text-xs text-danger">{errors.revenue.message}</p>}
      </div>

      <div className="flex gap-3">
        <Button type="button" variant="outline" className="flex-1 gap-2" onClick={onBack}>
          <ArrowLeft className="h-4 w-4" /> Back
        </Button>
        <Button type="submit" className="flex-1 gap-2">
          Continue <ArrowRight className="h-4 w-4" />
        </Button>
      </div>
    </form>
  );
}

function Step2({ onNext, onBack }: { onNext: () => void; onBack: () => void }) {
  const { data, setData } = useOnboardingStore();

  const flags = [
    {
      key: 'handlesPhi' as const,
      label: 'We handle Protected Health Information (PHI)',
      sublabel: 'Patient records, medical data, EHRs',
    },
    {
      key: 'handlesCui' as const,
      label: 'We handle Controlled Unclassified Information (CUI)',
      sublabel: 'Federal contract data, FOUO materials',
    },
    {
      key: 'isDodContractor' as const,
      label: 'We are a Department of Defense contractor',
      sublabel: 'DFARS, CMMC requirements apply',
    },
    {
      key: 'fedrampRequired' as const,
      label: 'FedRAMP authorization is required or anticipated',
      sublabel: 'Cloud services for federal agencies',
    },
  ];

  return (
    <div className="space-y-5">
      <p className="text-sm text-muted">
        These flags determine your compliance profile and which assessment questions apply.
      </p>
      <div className="space-y-3">
        {flags.map((flag) => (
          <label
            key={flag.key}
            className="flex items-start gap-3 rounded-lg border border-border bg-surface-2 p-4 cursor-pointer hover:border-primary/30 transition-colors"
          >
            <Checkbox
              checked={data[flag.key]}
              onCheckedChange={(checked) => setData({ [flag.key]: Boolean(checked) })}
              className="mt-0.5"
            />
            <div>
              <p className="text-sm font-medium text-foreground">{flag.label}</p>
              <p className="text-xs text-muted mt-0.5">{flag.sublabel}</p>
            </div>
          </label>
        ))}
      </div>
      <div className="flex gap-3">
        <Button type="button" variant="outline" className="flex-1 gap-2" onClick={onBack}>
          <ArrowLeft className="h-4 w-4" /> Back
        </Button>
        <Button className="flex-1 gap-2" onClick={onNext}>
          Continue <ArrowRight className="h-4 w-4" />
        </Button>
      </div>
    </div>
  );
}

function Step3({ onBack }: { onBack: () => void }) {
  const { data, setOrgId, setAssessmentId } = useOnboardingStore();
  const router = useRouter();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const price = tierPrice(data);

  const derivedProfile = () => {
    if (data.isDodContractor || data.handlesCui) return 'GovCon';
    if (data.handlesPhi || data.industry === 'banking' || data.industry === 'healthcare')
      return 'Regulated';
    const n = parseInt(data.employeeCount?.split('-')[0] ?? '0', 10);
    if (n > 200) return 'Enterprise';
    if (n > 50) return 'Mid-Market';
    return 'SMB';
  };

  const handleProceedToPayment = async () => {
    setLoading(true);
    setError('');
    try {
      // 1. Create org + draft assessment
      const org = await assessmentApi.createOrg({
        name: data.orgName,
        email: data.email,
        industry: data.industry,
        employee_count: data.employeeCount,
        revenue: data.revenue,
        handles_phi: data.handlesPhi,
        handles_cui: data.handlesCui,
        is_dod_contractor: data.isDodContractor,
        fedramp_required: data.fedrampRequired,
      });
      setOrgId(org.org_id);
      setAssessmentId(org.assessment_id);

      // 2. Create checkout session
      const checkout = await assessmentApi.createCheckout(org.assessment_id);

      // 3. Dev bypass: no Stripe key configured — go straight to assessment
      if (checkout.dev_bypass || !checkout.checkout_url) {
        router.push(`/assessment?id=${org.assessment_id}`);
        return;
      }

      // 4. Redirect to Stripe hosted checkout
      window.location.href = checkout.checkout_url;
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Something went wrong. Please try again.');
      setLoading(false);
    }
  };

  return (
    <div className="space-y-5">
      {/* Profile summary */}
      <div className="rounded-lg border border-border bg-surface-2 p-4 space-y-3">
        <h3 className="text-sm font-semibold text-foreground">Your assessment profile</h3>
        <div className="grid grid-cols-2 gap-y-2 text-sm">
          <span className="text-muted">Organization</span>
          <span className="text-foreground font-medium">{data.orgName}</span>
          <span className="text-muted">Email</span>
          <span className="text-foreground font-medium">{data.email}</span>
          <span className="text-muted">Industry</span>
          <span className="text-foreground font-medium capitalize">{data.industry}</span>
          <span className="text-muted">Team size</span>
          <span className="text-foreground font-medium">{data.employeeCount} employees</span>
          <span className="text-muted">Profile</span>
          <span className="text-primary font-medium">{derivedProfile()}</span>
        </div>
      </div>

      {/* Pricing */}
      <div className="rounded-lg border border-primary/30 bg-primary/5 p-4 flex items-center justify-between">
        <div>
          <p className="text-sm font-semibold text-foreground">One-time assessment fee</p>
          <p className="text-xs text-muted mt-0.5">
            Includes AI advisory report · {derivedProfile()} tier
          </p>
        </div>
        <p className="text-2xl font-bold text-primary">{price}</p>
      </div>

      {/* What you get */}
      <ul className="space-y-1.5">
        {[
          'Full AI governance risk scoring across 6 domains',
          'Claude-powered executive advisory report',
          'Prioritised 30/60/90-day remediation roadmap',
          'Compliance framework alignment (NIST, SOC 2, HIPAA, CMMC)',
        ].map((item) => (
          <li key={item} className="flex items-start gap-2 text-xs text-muted">
            <span className="text-success mt-0.5">✓</span>
            {item}
          </li>
        ))}
      </ul>

      {error && (
        <div className="rounded-lg border border-danger/30 bg-danger/5 px-4 py-3">
          <p className="text-sm text-danger">{error}</p>
        </div>
      )}

      <div className="flex gap-3">
        <Button type="button" variant="outline" className="flex-1 gap-2" onClick={onBack} disabled={loading}>
          <ArrowLeft className="h-4 w-4" /> Back
        </Button>
        <Button className="flex-1 gap-2" onClick={handleProceedToPayment} loading={loading}>
          <CreditCard className="h-4 w-4" /> Pay {price}
        </Button>
      </div>

      <p className="text-center text-xs text-muted">
        Secured by Stripe · No subscription · Cancel anytime
      </p>
    </div>
  );
}

// ─── Main wizard ─────────────────────────────────────────────────────────────

const STEPS = [
  { label: 'Organization', icon: Building2 },
  { label: 'Size', icon: Users },
  { label: 'Compliance', icon: Shield },
  { label: 'Review & Pay', icon: DollarSign },
];

export default function OnboardingPage() {
  const { step, setStep } = useOnboardingStore();

  const next = () => setStep(Math.min(step + 1, STEPS.length - 1));
  const back = () => setStep(Math.max(step - 1, 0));

  return (
    <div className="min-h-screen bg-background flex flex-col items-center justify-center px-4 py-16">
      {/* Logo */}
      <div className="flex items-center gap-2 mb-10">
        <div className="flex h-7 w-7 items-center justify-center rounded bg-primary">
          <Zap className="h-4 w-4 text-white" />
        </div>
        <span className="font-semibold text-foreground">FrostGate</span>
      </div>

      <Card className="w-full max-w-lg">
        <CardHeader>
          <CardTitle>AI Governance Assessment</CardTitle>
          <CardDescription>
            Step {step + 1} of {STEPS.length} — {STEPS[step].label}
          </CardDescription>
          <Progress value={((step + 1) / STEPS.length) * 100} className="mt-3" />
        </CardHeader>

        {/* Step indicators */}
        <div className="flex border-b border-border mb-6 px-6">
          {STEPS.map((s, i) => (
            <div
              key={s.label}
              className={`flex-1 flex flex-col items-center pb-3 text-xs transition-colors ${
                i === step
                  ? 'text-primary border-b-2 border-primary'
                  : i < step
                  ? 'text-success'
                  : 'text-muted'
              }`}
            >
              <s.icon className="h-4 w-4 mb-1" />
              <span className="hidden sm:block">{s.label}</span>
            </div>
          ))}
        </div>

        <CardContent>
          {step === 0 && <Step0 onNext={next} />}
          {step === 1 && <Step1 onNext={next} onBack={back} />}
          {step === 2 && <Step2 onNext={next} onBack={back} />}
          {step === 3 && <Step3 onBack={back} />}
        </CardContent>
      </Card>

      <p className="mt-6 text-xs text-muted text-center max-w-sm">
        Your data is used only to generate your assessment. We never share or sell it.
        Reports are aligned with, not certified to, applicable frameworks.
      </p>
    </div>
  );
}
