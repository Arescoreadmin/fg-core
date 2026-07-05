'use client';
import { useState } from 'react';
import PortalShell from './PortalShell';

const MCIM_ID = 'MCIM-18.6-PORTAL-SUPPORT';
const AUTHORITY = 'Support Center Authority';
const sourceOfTruth = '/api/core/field-assessment/engagements';
const drillDown = '/support';
const customerSafe = true;

export type SupportTopicCategory =
  | 'findings' | 'reports' | 'remediation' | 'attestation' | 'portal' | 'trust';

export interface SupportTopic {
  id: string;
  title: string;
  category: SupportTopicCategory;
  content: string;
}

interface Props {
  topics: SupportTopic[];
  contactEmail: string | null;
  loading: boolean;
  lastUpdated?: string;
}

const CATEGORY_LABEL: Record<SupportTopicCategory, string> = {
  findings: 'Findings',
  reports: 'Reports',
  remediation: 'Remediation',
  attestation: 'Attestation',
  portal: 'Portal',
  trust: 'Trust',
};

export default function SupportCenter({ topics, contactEmail, loading, lastUpdated }: Props) {
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const categories = Array.from(new Set(topics.map((t) => t.category)));

  return (
    <PortalShell
      mcimId={MCIM_ID}
      authority={AUTHORITY}
      capability="Customer Support Center"
      sourceOfTruth={sourceOfTruth}
      drillDown={drillDown}
      title="Support Center"
      lastUpdated={lastUpdated}
    >
      <section aria-label="support-center" data-testid="support-center">
        <div className="mb-4 rounded border border-border bg-muted/10 px-3 py-2 text-xs text-muted">
          Support content is provided by your operator for this engagement.
        </div>

        {loading && (
          <div className="space-y-2" aria-busy="true">
            {[1, 2, 3].map((i) => (
              <div key={i} className="h-10 rounded border border-border bg-surface-2 animate-pulse" />
            ))}
          </div>
        )}

        {!loading && topics.length === 0 && (
          <p className="text-sm text-muted text-center py-8">No support topics available.</p>
        )}

        {!loading && topics.length > 0 && (
          <div className="space-y-4">
            {categories.map((cat) => {
              const catTopics = topics.filter((t) => t.category === cat);
              return (
                <div key={cat}>
                  <p className="text-[10px] font-semibold uppercase tracking-wide text-muted/70 mb-2">
                    {CATEGORY_LABEL[cat]}
                  </p>
                  <div className="space-y-1">
                    {catTopics.map((topic) => {
                      const isOpen = expandedId === topic.id;
                      return (
                        <div key={topic.id} className="rounded border border-border overflow-hidden">
                          <button
                            type="button"
                            aria-expanded={isOpen}
                            className="flex w-full items-center justify-between px-3 py-2.5 text-left text-sm font-medium text-foreground hover:bg-surface-2 transition-colors"
                            onClick={() => setExpandedId(isOpen ? null : topic.id)}
                          >
                            <span>{topic.title}</span>
                            <span className="text-muted text-xs ml-2">{isOpen ? '▲' : '▼'}</span>
                          </button>
                          {isOpen && (
                            <div className="px-3 py-2.5 border-t border-border bg-surface text-xs text-muted leading-relaxed">
                              {topic.content}
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </div>
                </div>
              );
            })}
          </div>
        )}

        {!loading && contactEmail && (
          <div className="mt-4 border-t border-border pt-3 text-xs text-muted">
            For additional assistance, contact your operator at{' '}
            <span className="font-mono text-foreground">{contactEmail}</span>.
          </div>
        )}
      </section>
    </PortalShell>
  );
}

void MCIM_ID; void AUTHORITY; void sourceOfTruth; void drillDown; void customerSafe;
