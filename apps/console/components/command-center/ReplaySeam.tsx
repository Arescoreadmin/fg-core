'use client';

import { Clock } from 'lucide-react';
import { Button } from '@/components/ui/button';
import WidgetShell from './WidgetShell';

// MCIM reference: MCIM-18.6-CMD-CENTER
const MCIM_ID = 'MCIM-18.6-CMD-CENTER';
const AUTHORITY = 'Governance Intelligence Authority';
const sourceOfTruth = '/api/core/control-tower/snapshot';
const drillDown = '/dashboard/evaluation';

interface ReplayButton {
  id: string;
  label: string;
  description: string;
}

const REPLAY_BUTTONS: ReplayButton[] = [
  { id: 'last-week', label: 'Last Week', description: 'Replay governance state from last 7 days' },
  { id: 'last-month', label: 'Last Month', description: 'Replay governance state from last 30 days' },
  { id: 'snapshot', label: 'Snapshot', description: 'Replay from specific control tower snapshot' },
  { id: 'policy-version', label: 'Policy Version', description: 'Replay with historical policy version' },
  { id: 'simulation', label: 'Simulation', description: 'Simulate governance scenario replay' },
  { id: 'historical', label: 'Historical Comparison', description: 'Compare current vs historical state' },
];

interface ReplaySeamProps {
  loading?: boolean;
  lastUpdated?: string;
}

export default function ReplaySeam({
  loading = false,
  lastUpdated,
}: ReplaySeamProps) {
  return (
    <WidgetShell
      mcimId={MCIM_ID}
      authority={AUTHORITY}
      capability="Executive Replay"
      sourceOfTruth={sourceOfTruth}
      drillDown={drillDown}
      refreshPolicy="on-demand"
      lastUpdated={lastUpdated}
      title="Executive Replay"
    >
      <div aria-label="replay-seam" data-testid="replay-seam">
        {/* Unavailable banner */}
        <div
          aria-label="replay-unavailable"
          data-testid="replay-unavailable"
          className="mb-3 rounded-md border border-warning/30 bg-warning/5 px-3 py-2 text-[11px] text-warning"
        >
          <div className="flex items-center gap-2">
            <Clock className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
            <span>Replay not available from current authority data</span>
          </div>
        </div>

        {loading ? (
          <div className="space-y-2">
            {[1, 2, 3].map((i) => (
              <div key={i} className="h-10 w-full animate-pulse rounded bg-muted" />
            ))}
          </div>
        ) : (
          <div className="grid grid-cols-2 gap-2">
            {REPLAY_BUTTONS.map((btn) => (
              <Button
                key={btn.id}
                variant="outline"
                size="sm"
                disabled
                aria-disabled="true"
                data-testid={`replay-btn-${btn.id}`}
                aria-label={`replay-btn-${btn.id}`}
                className="h-auto flex-col gap-0.5 py-2 text-left opacity-40 cursor-not-allowed"
                title={btn.description}
              >
                <span className="text-[10px] font-medium">{btn.label}</span>
              </Button>
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
