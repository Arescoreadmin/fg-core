import type { DecisionOut } from '@/lib/coreApi';
import { RiskBadge } from '@/components/governance/RiskBadge';

function formatTs(ts?: string) {
  if (!ts) return '—';
  try { return new Date(ts).toLocaleString(); } catch { return ts; }
}

export function DecisionsTable({
  decisions,
  onSelect,
}: {
  decisions: DecisionOut[];
  onSelect: (id: string) => void;
}) {
  if (!decisions.length) {
    return (
      <div className="rounded-lg border border-dashed border-border px-4 py-8 text-center text-sm text-muted">
        No decisions yet — policy outcomes will appear here once traffic flows through FrostGate.
      </div>
    );
  }

  return (
    <div className="overflow-x-auto rounded-lg border border-border">
      <table className="w-full border-collapse text-sm">
        <thead>
          <tr className="border-b border-border bg-surface-2">
            {['ID', 'Event', 'Threat', 'Type', 'Created'].map((h) => (
              <th
                key={h}
                className="px-4 py-2.5 text-left text-[10px] font-semibold uppercase tracking-widest text-muted/70"
              >
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {decisions.map((d) => (
            <tr
              key={d.id}
              onClick={() => onSelect(d.id)}
              className="cursor-pointer border-b border-border last:border-0 hover:bg-surface-2 transition-colors"
            >
              <td className="px-4 py-2.5 font-mono text-xs text-muted/80 max-w-[120px] truncate">{d.id}</td>
              <td className="px-4 py-2.5 font-mono text-xs text-muted/80 max-w-[120px] truncate">{d.event_id || '—'}</td>
              <td className="px-4 py-2.5">
                <RiskBadge level={d.threat_level} />
              </td>
              <td className="px-4 py-2.5 text-xs text-muted">{d.event_type || '—'}</td>
              <td className="px-4 py-2.5 text-xs text-muted">{formatTs(d.created_at)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
