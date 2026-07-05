'use client';
import PortalShell from './PortalShell';

const MCIM_ID = 'MCIM-18.6-PORTAL-TRUST-STORY';
const AUTHORITY = 'Customer Trust Story Authority';
const sourceOfTruth = '/api/core/field-assessment/engagements';
const drillDown = '/trust';
const customerSafe = true;

export interface TrustStory {
  improvements: string[];
  regressions: string[];
  highestRisk: string | null;
  customerActionNeeded: string | null;
  generatedAt: string;
  isAuthorityBacked: true;
}

interface Props {
  story: TrustStory | null;
  loading: boolean;
  lastUpdated?: string;
}

function SectionTitle({ children }: { children: React.ReactNode }) {
  return (
    <h3 className="text-xs font-semibold text-muted uppercase tracking-wider">{children}</h3>
  );
}

export default function CustomerTrustStory({ story, loading, lastUpdated }: Props) {
  return (
    <PortalShell
      mcimId={MCIM_ID}
      authority={AUTHORITY}
      capability="Customer Trust Story"
      sourceOfTruth={sourceOfTruth}
      drillDown={drillDown}
      title="Trust Story"
      lastUpdated={lastUpdated}
    >
      {loading && (
        <div className="space-y-3" aria-busy="true">
          {[1, 2, 3, 4].map((i) => (
            <div key={i} className="h-6 rounded bg-surface-2 animate-pulse w-4/5" />
          ))}
        </div>
      )}

      {!loading && !story && (
        <p className="text-sm text-muted text-center py-8">
          Trust story not yet available for this engagement.
        </p>
      )}

      {!loading && story && (
        <div className="space-y-5">
          {/* What Improved */}
          <section className="space-y-2">
            <SectionTitle>What Improved</SectionTitle>
            {story.improvements.length > 0 ? (
              <ul className="space-y-1">
                {story.improvements.map((item, i) => (
                  <li key={i} className="flex gap-2 text-sm text-foreground">
                    <span className="text-green-300 shrink-0">+</span>
                    <span>{item}</span>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="text-sm text-muted">No improvements recorded in this period</p>
            )}
          </section>

          {/* What Regressed */}
          <section className="space-y-2">
            <SectionTitle>What Regressed</SectionTitle>
            {story.regressions.length > 0 ? (
              <ul className="space-y-1">
                {story.regressions.map((item, i) => (
                  <li key={i} className="flex gap-2 text-sm text-foreground">
                    <span className="text-red-300 shrink-0">−</span>
                    <span>{item}</span>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="text-sm text-muted">No regressions recorded in this period</p>
            )}
          </section>

          {/* Highest Risk */}
          <section className="space-y-1">
            <SectionTitle>Highest Risk</SectionTitle>
            <p className="text-sm text-foreground">
              {story.highestRisk ?? 'No critical risks identified at this time'}
            </p>
          </section>

          {/* Action Needed */}
          <section className="space-y-1">
            <SectionTitle>Action Needed</SectionTitle>
            <p className="text-sm text-foreground">
              {story.customerActionNeeded ?? 'No immediate customer action required'}
            </p>
          </section>

          <p className="text-[11px] text-muted border-t border-border pt-3">
            This summary is deterministic and authority-backed. No AI-generated or speculative content.
          </p>
          <p className="text-[10px] text-muted">
            Generated: {new Date(story.generatedAt).toLocaleString()}
          </p>
        </div>
      )}
    </PortalShell>
  );
}

void MCIM_ID; void AUTHORITY; void sourceOfTruth; void drillDown; void customerSafe;
