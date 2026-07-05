'use client';
import PortalShell from './PortalShell';

const MCIM_ID = 'MCIM-18.6-PORTAL-AUDIT-EVENTS';
const AUTHORITY = 'Audit Events Log Authority';
const sourceOfTruth = '/api/core/field-assessment/engagements';
const drillDown = '/trust';
const customerSafe = true;

export interface PortalAuditEvent {
  id: string;
  eventType: string;
  actor: string;
  reasonCode: string | null;
  createdAt: string;
}

interface Props {
  events: PortalAuditEvent[];
  loading: boolean;
  lastUpdated?: string;
}

export default function AuditEventsLog({ events, loading, lastUpdated }: Props) {
  const sorted = [...events].sort(
    (a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime(),
  );

  return (
    <PortalShell
      mcimId={MCIM_ID}
      authority={AUTHORITY}
      capability="Portal Audit Events"
      sourceOfTruth={sourceOfTruth}
      drillDown={drillDown}
      title="Audit Events"
      lastUpdated={lastUpdated}
    >
      <section aria-label="audit-events-log" data-testid="audit-events-log">
        <div className="mb-3 rounded border border-border bg-muted/10 px-3 py-2 text-xs text-muted">
          Audit events represent portal-visible governance actions for this engagement.
        </div>

        {loading && (
          <div className="space-y-2" aria-busy="true">
            {[1, 2, 3, 4].map((i) => (
              <div key={i} className="h-10 rounded border border-border bg-surface-2 animate-pulse" />
            ))}
          </div>
        )}

        {!loading && sorted.length === 0 && (
          <p className="text-sm text-muted text-center py-8">No audit events recorded.</p>
        )}

        {!loading && sorted.length > 0 && (
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-border text-muted text-left">
                  <th className="pb-2 pr-4 font-medium">Event Type</th>
                  <th className="pb-2 pr-4 font-medium">Actor</th>
                  <th className="pb-2 pr-4 font-medium">Reason</th>
                  <th className="pb-2 font-medium">Timestamp</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {sorted.map((event) => (
                  <tr key={event.id} className="text-foreground">
                    <td className="py-2 pr-4 font-mono">{event.eventType}</td>
                    <td className="py-2 pr-4 text-muted">{event.actor}</td>
                    <td className="py-2 pr-4 text-muted">{event.reasonCode ?? '—'}</td>
                    <td className="py-2 text-muted">{new Date(event.createdAt).toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </PortalShell>
  );
}

void MCIM_ID; void AUTHORITY; void sourceOfTruth; void drillDown; void customerSafe;
