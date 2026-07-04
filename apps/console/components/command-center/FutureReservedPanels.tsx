'use client';

import WidgetShell from './WidgetShell';

// MCIM reference: MCIM-18.6-CMD-CENTER
const MCIM_ID = 'MCIM-18.6-CMD-CENTER';
const AUTHORITY = 'Control Tower Authority';
const sourceOfTruth = '/api/core/control-tower/snapshot';
const drillDown = '/dashboard';

interface FutureCapability {
  id: string;
  label: string;
  description: string;
}

const FUTURE_CAPABILITIES: FutureCapability[] = [
  {
    id: 'future-autonomous-governance',
    label: 'Autonomous Governance',
    description: 'AI-driven autonomous governance decision engine',
  },
  {
    id: 'future-agi-oversight',
    label: 'AGI Oversight',
    description: 'Advanced governance oversight for AGI systems',
  },
  {
    id: 'future-predictive-risk',
    label: 'Predictive Risk',
    description: 'ML-based predictive risk assessment and forecasting',
  },
  {
    id: 'future-executive-copilot',
    label: 'Executive Copilot',
    description: 'AI-assisted executive decision support',
  },
  {
    id: 'future-autonomous-remediation',
    label: 'Autonomous Remediation',
    description: 'Automated remediation action execution',
  },
  {
    id: 'future-digital-twin',
    label: 'Digital Twin',
    description: 'Digital twin governance environment simulation',
  },
  {
    id: 'future-cross-tenant-benchmark',
    label: 'Cross-Tenant Benchmark',
    description: 'Anonymized cross-tenant governance benchmarking',
  },
  {
    id: 'future-regulatory-intelligence',
    label: 'Regulatory Intelligence',
    description: 'Real-time regulatory change intelligence and impact analysis',
  },
  {
    id: 'future-behavior-analytics',
    label: 'Behavior Analytics',
    description: 'User and system behavior analytics for governance',
  },
  {
    id: 'future-continuous-assurance',
    label: 'Continuous Assurance',
    description: 'Always-on continuous compliance assurance engine',
  },
];

interface FutureReservedPanelsProps {
  loading?: boolean;
  lastUpdated?: string;
}

export default function FutureReservedPanels({
  loading = false,
  lastUpdated,
}: FutureReservedPanelsProps) {
  return (
    <WidgetShell
      mcimId={MCIM_ID}
      authority={AUTHORITY}
      capability="Future Capabilities"
      sourceOfTruth={sourceOfTruth}
      drillDown={drillDown}
      refreshPolicy="static"
      lastUpdated={lastUpdated}
      title="Future Capabilities"
    >
      <div aria-label="future-reserved-panels" data-testid="future-reserved-panels">
        <p className="mb-3 text-[10px] text-muted">
          These capabilities are reserved for future development. They are not active.
        </p>

        {loading ? (
          <div className="space-y-2">
            {[1, 2, 3].map((i) => (
              <div key={i} className="h-10 w-full animate-pulse rounded bg-muted" />
            ))}
          </div>
        ) : (
          <div className="grid gap-2 sm:grid-cols-2">
            {FUTURE_CAPABILITIES.map((cap) => (
              <div
                key={cap.id}
                data-testid={cap.id}
                aria-label={cap.id}
                aria-disabled="true"
                className="rounded-md border border-border/50 bg-muted/10 px-3 py-2 opacity-50 cursor-not-allowed"
              >
                <p className="text-[11px] font-medium text-foreground">{cap.label}</p>
                <p className="text-[9px] text-muted mt-0.5">Capability reserved — not available</p>
              </div>
            ))}
          </div>
        )}

        <p className="mt-3 text-[9px] text-muted/50">
          Authority: {AUTHORITY} · {MCIM_ID}
        </p>
      </div>
    </WidgetShell>
  );
}
