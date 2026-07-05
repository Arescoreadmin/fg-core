'use client';
import PortalShell from './PortalShell';

const MCIM_ID = 'MCIM-18.6-PORTAL-ENGAGEMENT';
const AUTHORITY = 'Engagement Overview Authority';
const sourceOfTruth = '/api/core/field-assessment/engagements';
const drillDown = '/engagement';
const customerSafe = true;

export interface EngagementOverviewData {
  id: string;
  name: string;
  scope: string | null;
  status: string;
  assessmentType: string;
  frameworks: string[];
  createdAt: string;
  updatedAt: string;
  deliveryMilestones: string[];
  portalPublicationState: string | null;
  customerNextSteps: string[];
}

interface Props {
  engagement: EngagementOverviewData | null;
  loading: boolean;
  lastUpdated?: string;
}

const STATUS_CLASS: Record<string, string> = {
  active: 'border-green-500/40 bg-green-500/10 text-green-300',
  completed: 'border-blue-500/40 bg-blue-500/10 text-blue-300',
  draft: 'border-border bg-surface-2 text-muted',
  pending: 'border-amber-500/40 bg-amber-500/10 text-amber-200',
};

function StatusBadge({ status }: { status: string }) {
  const cls = STATUS_CLASS[status] ?? STATUS_CLASS.draft;
  return (
    <span className={`inline-flex items-center rounded px-1.5 py-0.5 text-xs border font-medium ${cls}`}>
      {status.charAt(0).toUpperCase() + status.slice(1).replace(/_/g, ' ')}
    </span>
  );
}

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex flex-col sm:flex-row sm:items-start gap-1 sm:gap-4 text-sm">
      <span className="w-44 shrink-0 text-muted text-xs font-medium uppercase tracking-wide pt-0.5">
        {label}
      </span>
      <span className="text-foreground flex-1">{children}</span>
    </div>
  );
}

export default function EngagementOverview({ engagement, loading, lastUpdated }: Props) {
  return (
    <PortalShell
      mcimId={MCIM_ID}
      authority={AUTHORITY}
      capability="Engagement Overview"
      sourceOfTruth={sourceOfTruth}
      drillDown={drillDown}
      title="Engagement Overview"
      lastUpdated={lastUpdated}
    >
      <section aria-label="engagement-overview" data-testid="engagement-overview">
      {loading && (
        <div className="space-y-3" aria-busy="true">
          {[1, 2, 3, 4, 5].map((i) => (
            <div key={i} className="h-5 rounded bg-surface-2 animate-pulse w-3/4" />
          ))}
        </div>
      )}

      {!loading && !engagement && (
        <p className="text-sm text-muted text-center py-8">No engagement data available.</p>
      )}

      {!loading && engagement && (
        <div className="space-y-3">
          <Row label="Name">{engagement.name}</Row>
          <Row label="Status">
            <StatusBadge status={engagement.status} />
          </Row>
          <Row label="Scope">
            {engagement.scope ?? <span className="text-muted">Not specified</span>}
          </Row>
          <Row label="Assessment Type">{engagement.assessmentType}</Row>
          <Row label="Frameworks">
            {engagement.frameworks.length > 0
              ? engagement.frameworks.join(', ')
              : <span className="text-muted">None specified</span>}
          </Row>
          <Row label="Created">{new Date(engagement.createdAt).toLocaleString()}</Row>
          <Row label="Updated">{new Date(engagement.updatedAt).toLocaleString()}</Row>
          <Row label="Publication State">
            {engagement.portalPublicationState ?? <span className="text-muted">Not set</span>}
          </Row>

          {engagement.deliveryMilestones.length > 0 && (
            <Row label="Delivery Milestones">
              <ul className="space-y-1">
                {engagement.deliveryMilestones.map((m, i) => (
                  <li key={i} className="text-sm text-foreground">• {m}</li>
                ))}
              </ul>
            </Row>
          )}

          {engagement.customerNextSteps.length > 0 && (
            <Row label="Next Steps">
              <ol className="space-y-1">
                {engagement.customerNextSteps.map((step, i) => (
                  <li key={i} className="text-sm text-foreground">{i + 1}. {step}</li>
                ))}
              </ol>
            </Row>
          )}

          <p className="text-[11px] text-muted border-t border-border pt-3 mt-3">
            Internal operator notes are not displayed in this view.
          </p>
        </div>
      )}
      </section>
    </PortalShell>
  );
}

void MCIM_ID; void AUTHORITY; void sourceOfTruth; void drillDown; void customerSafe;
