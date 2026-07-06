'use client';

import { useEffect, useState } from 'react';
import {
  getOperationalBriefing,
  type OperationalBriefingResult,
  type BriefingLine,
} from '@/lib/operationsCenterApi';

type BriefingCategory = BriefingLine['category'];

const CATEGORY_BADGE: Record<BriefingCategory, { label: string; classes: string }> = {
  changed:              { label: 'Changed',            classes: 'border-blue-500/30 bg-blue-500/10 text-blue-400' },
  risk_increased:       { label: 'Risk +',             classes: 'border-red-500/30 bg-red-500/10 text-red-400' },
  risk_reduced:         { label: 'Risk −',             classes: 'border-green-500/30 bg-green-500/10 text-green-400' },
  evidence_added:       { label: 'Evidence +',         classes: 'border-green-500/30 bg-green-500/10 text-green-400' },
  evidence_missing:     { label: 'Evidence Missing',   classes: 'border-yellow-500/30 bg-yellow-500/10 text-yellow-400' },
  policy_triggered:     { label: 'Policy',             classes: 'border-orange-500/30 bg-orange-500/10 text-orange-400' },
  automation_executed:  { label: 'Automation',         classes: 'border-blue-500/30 bg-blue-500/10 text-blue-400' },
  approval_required:    { label: 'Approval Required',  classes: 'border-orange-500/30 bg-orange-500/10 text-orange-400' },
  business_impact:      { label: 'Business Impact',    classes: 'border-purple-500/30 bg-purple-500/10 text-purple-400' },
  confidence:           { label: 'Confidence',         classes: 'border-border bg-surface text-muted' },
  unknown:              { label: 'Unknown',             classes: 'border-border bg-surface text-muted' },
};

const CATEGORY_ORDER: BriefingCategory[] = [
  'risk_increased', 'approval_required', 'policy_triggered', 'automation_executed',
  'business_impact', 'changed', 'risk_reduced', 'evidence_added', 'evidence_missing',
  'confidence', 'unknown',
];

function groupByCategory(lines: BriefingLine[]): Map<BriefingCategory, BriefingLine[]> {
  const map = new Map<BriefingCategory, BriefingLine[]>();
  for (const line of lines) {
    const existing = map.get(line.category) ?? [];
    map.set(line.category, [...existing, line]);
  }
  return map;
}

export default function ExecutiveOperationalBriefing() {
  const [result, setResult] = useState<OperationalBriefingResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    getOperationalBriefing().then((res) => {
      if (res.ok) {
        setResult(res.data);
      } else {
        setError(res.error);
      }
      setLoading(false);
    });
  }, []);

  return (
    <div
      data-mcim="MCIM-18.7-BRIEFING"
      className="rounded-lg border border-border bg-surface-2 p-4"
    >
      <h2 className="mb-3 text-xs font-semibold uppercase tracking-widest text-muted/70">
        Executive Operational Briefing
      </h2>

      {loading && (
        <p className="text-sm text-muted" aria-live="polite">Loading…</p>
      )}

      {!loading && error && (
        <p className="text-sm text-danger" role="alert" aria-label="Error loading briefing">
          {error}
        </p>
      )}

      {!loading && !error && result && (
        <>
          {!result.sufficientEvidence && (
            <div
              className="mb-4 rounded border border-yellow-500/40 bg-yellow-500/10 px-4 py-3"
              role="alert"
              aria-label="Insufficient evidence notice"
            >
              <p className="text-sm font-medium text-yellow-400">
                {result.insufficiencyReason}
              </p>
            </div>
          )}

          {result.sufficientEvidence && (
            <div className="space-y-3" aria-label="Briefing lines">
              {CATEGORY_ORDER.map((cat) => {
                const grouped = groupByCategory(result.lines);
                const lines = grouped.get(cat);
                if (!lines || lines.length === 0) return null;
                const badge = CATEGORY_BADGE[cat];
                return (
                  <div key={cat}>
                    <span
                      className={`mb-2 inline-block rounded border px-1.5 py-0.5 text-xs font-medium ${badge.classes}`}
                      aria-label={`Category: ${badge.label}`}
                    >
                      {badge.label}
                    </span>
                    <ul className="space-y-1" role="list">
                      {lines.map((line, idx) => (
                        <li
                          key={`${cat}-${idx}`}
                          role="listitem"
                          aria-label={`${line.label}: ${line.value}`}
                          className="flex flex-wrap items-baseline gap-2 text-xs"
                        >
                          <span className="text-muted">{line.label}</span>
                          <span className="font-medium text-foreground">{line.value}</span>
                          <span className="text-muted/60" aria-label={`Authority: ${line.authority}`}>
                            {line.authority}
                          </span>
                        </li>
                      ))}
                    </ul>
                  </div>
                );
              })}
            </div>
          )}

          <div className="mt-4 flex flex-wrap items-center gap-4 border-t border-border pt-3 text-xs text-muted">
            <span aria-label="Generated at">{result.generatedAt}</span>
            <span aria-label={`Derived from ${result.authorityCount} authoritative sources`}>
              Derived from {result.authorityCount} authoritative source{result.authorityCount !== 1 ? 's' : ''}
            </span>
          </div>
        </>
      )}
    </div>
  );
}
