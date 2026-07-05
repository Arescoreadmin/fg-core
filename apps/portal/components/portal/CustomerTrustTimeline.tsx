'use client';
import PortalShell from './PortalShell';

const MCIM_ID = 'MCIM-18.6-PORTAL-TIMELINE';
const AUTHORITY = 'Customer Trust Timeline Authority';
const sourceOfTruth = '/api/core/field-assessment/engagements';
const drillDown = '/timeline';
const customerSafe = true;

export type CustomerTimelineEventType =
  | 'assessment-started' | 'evidence-collected' | 'evidence-verified'
  | 'report-generated' | 'report-published' | 'remediation-opened'
  | 'remediation-completed' | 'attestation-submitted' | 'verification-completed'
  | 'portal-update';

export interface CustomerTimelineEvent {
  id: string;
  eventType: CustomerTimelineEventType;
  label: string;
  timestamp: string;
  sourceAuthority: string;
  drillDown: string | null;
  isPortalSafe: true;
}

interface Props {
  events: CustomerTimelineEvent[];
  loading: boolean;
  lastUpdated?: string;
}

const EVENT_DOT_CLASS: Record<CustomerTimelineEventType, string> = {
  'assessment-started': 'bg-blue-400',
  'evidence-collected': 'bg-amber-400',
  'evidence-verified': 'bg-amber-400',
  'report-generated': 'bg-green-400',
  'report-published': 'bg-green-400',
  'remediation-opened': 'bg-orange-400',
  'remediation-completed': 'bg-orange-400',
  'attestation-submitted': 'bg-purple-400',
  'verification-completed': 'bg-teal-400',
  'portal-update': 'bg-surface-3',
};

export default function CustomerTrustTimeline({ events, loading, lastUpdated }: Props) {
  const sorted = [...events].sort(
    (a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime(),
  );

  return (
    <PortalShell
      mcimId={MCIM_ID}
      authority={AUTHORITY}
      capability="Customer Trust Timeline"
      sourceOfTruth={sourceOfTruth}
      drillDown={drillDown}
      title="Trust Timeline"
      lastUpdated={lastUpdated}
    >
      <section aria-label="customer-trust-timeline" data-testid="customer-trust-timeline">
      <p className="text-[11px] text-muted mb-4">
        Only portal-safe events are shown. Internal operational audit details are not displayed.
      </p>

      {loading && (
        <div className="space-y-3" aria-busy="true">
          {[1, 2, 3, 4].map((i) => (
            <div key={i} className="h-12 rounded border border-border bg-surface-2 animate-pulse" />
          ))}
        </div>
      )}

      {!loading && sorted.length === 0 && (
        <p className="text-sm text-muted text-center py-8">No timeline events available.</p>
      )}

      {!loading && sorted.length > 0 && (
        <div className="relative">
          {/* Vertical line */}
          <div className="absolute left-3 top-0 bottom-0 w-px bg-border" aria-hidden="true" />

          <ol className="space-y-4">
            {sorted.map((event) => (
              <li key={event.id} className="flex gap-4 relative">
                <div
                  className={`mt-1.5 h-2.5 w-2.5 rounded-full shrink-0 z-10 ${EVENT_DOT_CLASS[event.eventType] ?? 'bg-surface-3'}`}
                  aria-hidden="true"
                />
                <div className="flex-1 min-w-0">
                  <div className="flex flex-wrap items-baseline gap-2">
                    <span className="text-sm font-medium text-foreground">{event.label}</span>
                    {event.drillDown && (
                      <a
                        href={event.drillDown}
                        className="text-xs text-primary hover:underline"
                      >
                        Details →
                      </a>
                    )}
                  </div>
                  <div className="flex flex-wrap gap-3 mt-0.5 text-[11px] text-muted">
                    <span>{event.sourceAuthority}</span>
                    <span>{new Date(event.timestamp).toLocaleString()}</span>
                  </div>
                </div>
              </li>
            ))}
          </ol>
        </div>
      )}
      </section>
    </PortalShell>
  );
}

void MCIM_ID; void AUTHORITY; void sourceOfTruth; void drillDown; void customerSafe;
