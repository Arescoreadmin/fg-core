'use client';

import { Suspense, useState } from 'react';
import { useRouter } from 'next/navigation';

const INDUSTRIES = [
  { value: 'technology', label: 'Technology / SaaS' },
  { value: 'healthcare', label: 'Healthcare / Life Sciences' },
  { value: 'banking', label: 'Banking / Financial Services' },
  { value: 'insurance', label: 'Insurance' },
  { value: 'government', label: 'Government / Public Sector' },
  { value: 'defense', label: 'Defense / Aerospace' },
  { value: 'manufacturing', label: 'Manufacturing / Industrial' },
  { value: 'retail', label: 'Retail / E-commerce' },
  { value: 'education', label: 'Education' },
  { value: 'other', label: 'Other' },
];

const EMPLOYEE_COUNTS = [
  { value: '1-10', label: '1–10 employees' },
  { value: '11-50', label: '11–50 employees' },
  { value: '51-200', label: '51–200 employees' },
  { value: '201-500', label: '201–500 employees' },
  { value: '501-1000', label: '501–1,000 employees' },
  { value: '1001-5000', label: '1,001–5,000 employees' },
  { value: '5001+', label: '5,000+ employees' },
];

function AssessmentIntakeForm() {
  const router = useRouter();

  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [industry, setIndustry] = useState('');
  const [employeeCount, setEmployeeCount] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      const res = await fetch('/api/assessment/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, email, industry, employee_count: employeeCount }),
      });

      const data = (await res.json().catch(() => ({}))) as { checkout_url?: string; error?: string };

      if (!res.ok) {
        setError(data.error ?? 'Something went wrong. Please try again.');
        setLoading(false);
        return;
      }

      if (!data.checkout_url) {
        setError('Could not create checkout session. Please try again.');
        setLoading(false);
        return;
      }

      // Redirect to Stripe — keep loading state so the button stays disabled.
      window.location.assign(data.checkout_url);
    } catch {
      setError('Network error. Please check your connection and try again.');
      setLoading(false);
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-background px-4 py-12">
      <div className="w-full max-w-md space-y-6">
        <div className="text-center space-y-1">
          <p className="text-lg font-semibold text-foreground">FrostGate</p>
          <p className="text-sm text-muted">AI Governance Assessment</p>
        </div>

        <form
          onSubmit={handleSubmit}
          className="rounded border border-border bg-surface-2 p-6 space-y-4"
        >
          <div className="space-y-1">
            <h1 className="text-sm font-semibold text-foreground">Start your assessment</h1>
            <p className="text-xs text-muted">
              Tell us about your organization. We&apos;ll tailor your AI governance risk report to
              your profile.
            </p>
          </div>

          <div className="space-y-1.5">
            <label htmlFor="name" className="block text-xs font-medium text-muted">
              Organization name <span className="text-red-400">*</span>
            </label>
            <input
              id="name"
              type="text"
              required
              autoComplete="organization"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="Acme Corp"
              disabled={loading}
              className="w-full rounded border border-border bg-surface px-3 py-2 text-sm text-foreground placeholder-muted focus:outline-none focus:ring-1 focus:ring-primary disabled:opacity-50"
            />
          </div>

          <div className="space-y-1.5">
            <label htmlFor="email" className="block text-xs font-medium text-muted">
              Work email <span className="text-red-400">*</span>
            </label>
            <input
              id="email"
              type="email"
              required
              autoComplete="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="you@acme.com"
              disabled={loading}
              className="w-full rounded border border-border bg-surface px-3 py-2 text-sm text-foreground placeholder-muted focus:outline-none focus:ring-1 focus:ring-primary disabled:opacity-50"
            />
          </div>

          <div className="space-y-1.5">
            <label htmlFor="industry" className="block text-xs font-medium text-muted">
              Industry
            </label>
            <select
              id="industry"
              value={industry}
              onChange={(e) => setIndustry(e.target.value)}
              disabled={loading}
              className="w-full rounded border border-border bg-surface px-3 py-2 text-sm text-foreground focus:outline-none focus:ring-1 focus:ring-primary disabled:opacity-50"
            >
              <option value="">Select your industry</option>
              {INDUSTRIES.map((opt) => (
                <option key={opt.value} value={opt.value}>
                  {opt.label}
                </option>
              ))}
            </select>
          </div>

          <div className="space-y-1.5">
            <label htmlFor="employee_count" className="block text-xs font-medium text-muted">
              Organization size
            </label>
            <select
              id="employee_count"
              value={employeeCount}
              onChange={(e) => setEmployeeCount(e.target.value)}
              disabled={loading}
              className="w-full rounded border border-border bg-surface px-3 py-2 text-sm text-foreground focus:outline-none focus:ring-1 focus:ring-primary disabled:opacity-50"
            >
              <option value="">Select size</option>
              {EMPLOYEE_COUNTS.map((opt) => (
                <option key={opt.value} value={opt.value}>
                  {opt.label}
                </option>
              ))}
            </select>
          </div>

          {error && (
            <p role="alert" className="text-xs text-red-400">
              {error}
            </p>
          )}

          <button
            type="submit"
            disabled={loading || !name.trim() || !email.trim()}
            className="w-full rounded bg-primary px-4 py-2.5 text-sm font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
          >
            {loading ? 'Preparing checkout…' : 'Continue to payment'}
          </button>
        </form>

        <p className="text-center text-xs text-muted">
          Already have an account?{' '}
          <a href="/login" className="text-primary hover:underline">
            Sign in
          </a>
        </p>

        <p className="text-center text-xs text-muted">
          Secure payment by Stripe. One-time payment · No subscription required.
        </p>
      </div>
    </div>
  );
}

export default function AssessmentPage() {
  return (
    <Suspense>
      <AssessmentIntakeForm />
    </Suspense>
  );
}
