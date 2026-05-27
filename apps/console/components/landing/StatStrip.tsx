'use client';

import { useEffect, useRef, useState } from 'react';

const STATS = [
  {
    value: 35,
    suffix: '–130',
    label: 'Questions per assessment',
    sub: 'Profile-tuned to your industry, size, and regulatory exposure',
  },
  {
    value: 6,
    suffix: '',
    label: 'Governance domains scored',
    sub: 'Data · Security · AI Maturity · Infra · Compliance · Automation',
  },
  {
    value: 15,
    suffix: '+',
    label: 'Compliance frameworks mapped',
    sub: 'NIST AI RMF · HIPAA · FFIEC · CMMC · SOC 2 · ISO 27001 · and more',
  },
  {
    value: 48,
    suffix: ' hrs',
    label: 'Average time to advisory report',
    sub: 'From assessment submission to a report you can present to your board',
  },
];

function useCountUp(target: number, duration: number, started: boolean) {
  const [count, setCount] = useState(0);
  useEffect(() => {
    if (!started) return;
    let startTime: number | null = null;
    const tick = (ts: number) => {
      if (!startTime) startTime = ts;
      const progress = Math.min((ts - startTime) / duration, 1);
      // Ease-out cubic
      const eased = 1 - Math.pow(1 - progress, 3);
      setCount(Math.round(eased * target));
      if (progress < 1) requestAnimationFrame(tick);
    };
    requestAnimationFrame(tick);
  }, [target, duration, started]);
  return count;
}

function StatItem({ value, suffix, label, sub, started }: (typeof STATS)[0] & { started: boolean }) {
  const count = useCountUp(value, 1200, started);
  return (
    <div className="text-center px-4 py-6 border-b border-border last:border-b-0 sm:border-b-0 sm:border-r sm:last:border-r-0">
      <div className="flex items-baseline justify-center gap-0.5">
        <span className="text-3xl font-bold text-foreground tabular-nums">{count}</span>
        <span className="text-lg font-semibold text-primary">{suffix}</span>
      </div>
      <p className="mt-1 text-sm font-medium text-foreground">{label}</p>
      <p className="mt-0.5 text-xs text-muted leading-relaxed max-w-[220px] mx-auto">{sub}</p>
    </div>
  );
}

export function StatStrip() {
  const ref = useRef<HTMLDivElement>(null);
  const [started, setStarted] = useState(false);

  useEffect(() => {
    if (!ref.current) return;
    const obs = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting) {
          setStarted(true);
          obs.disconnect();
        }
      },
      { threshold: 0.3 }
    );
    obs.observe(ref.current);
    return () => obs.disconnect();
  }, []);

  return (
    <div ref={ref} className="grid sm:grid-cols-4 border border-border rounded-xl bg-surface-2 overflow-hidden">
      {STATS.map((s) => (
        <StatItem key={s.label} {...s} started={started} />
      ))}
    </div>
  );
}
