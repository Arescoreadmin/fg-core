import type { DecisionOut } from '@/lib/coreApi';
import { RiskBadge, PolicyDecision, EvidenceCard, TrustIndicator, ConfidenceMeter } from '@/components/governance';
import type { EvidenceField } from '@/components/governance';

const KNOWN_FIELDS = new Set([
  'id', 'tenant_id', 'source', 'event_id', 'event_type',
  'threat_level', 'created_at', 'explain_summary',
  'decision_type', 'action', 'severity', 'confidence',
  'policy', 'reason', 'chain_status', 'request_id', 'response_hash',
]);

function formatTs(ts?: string) {
  if (!ts) return '—';
  try {
    return new Date(ts).toLocaleString();
  } catch {
    return ts;
  }
}

export function DecisionPanel({ decision }: { decision: DecisionOut }) {
  const action = String(decision.action ?? decision.decision_type ?? '');
  const confidence =
    decision.confidence !== undefined ? Number(decision.confidence) : undefined;
  const chainStatus = String(decision.chain_status ?? 'unknown');

  // Core evidence fields
  const coreFields: EvidenceField[] = [
    { label: 'ID', value: decision.id },
    { label: 'Tenant', value: decision.tenant_id },
    { label: 'Source', value: decision.source },
    { label: 'Event ID', value: decision.event_id },
    { label: 'Event Type', value: decision.event_type },
    { label: 'Severity', value: String(decision.severity ?? '—') },
    { label: 'Created', value: formatTs(decision.created_at) },
  ];

  // Any extra unknown fields not in the known set
  const extraFields: EvidenceField[] = Object.entries(decision)
    .filter(([k]) => !KNOWN_FIELDS.has(k))
    .map(([k, v]) => ({
      label: k,
      value: typeof v === 'object' ? JSON.stringify(v) : String(v ?? ''),
    }));

  return (
    <div className="space-y-4 rounded-xl border border-border bg-surface p-5">
      {/* Header */}
      <div className="flex flex-wrap items-start gap-3 border-b border-border pb-4">
        <div className="flex-1 min-w-0">
          <div className="flex flex-wrap items-center gap-2 mb-1">
            <RiskBadge level={decision.threat_level} />
            {action && <PolicyDecision action={action} policy={String(decision.policy ?? '')} reason={String(decision.reason ?? '')} />}
          </div>
          <p className="font-mono text-[10px] text-muted/60">
            {decision.tenant_id} · {formatTs(decision.created_at)}
          </p>
        </div>
      </div>

      {/* Summary */}
      {decision.explain_summary ? (
        <p className="text-sm text-foreground leading-relaxed">{String(decision.explain_summary)}</p>
      ) : (
        <p className="text-sm text-muted/60 italic">No explanation summary available.</p>
      )}

      {/* Confidence */}
      {confidence !== undefined && (
        <ConfidenceMeter value={confidence} />
      )}

      {/* Evidence */}
      <EvidenceCard title="Evidence" fields={coreFields} />

      {/* Trust proof */}
      <TrustIndicator
        status={chainStatus}
        requestId={String(decision.request_id ?? '')}
        hash={String(decision.response_hash ?? '')}
      />

      {/* Extra fields — collapsed into a secondary card */}
      {extraFields.length > 0 && (
        <EvidenceCard title="Additional fields" fields={extraFields} />
      )}
    </div>
  );
}
