'use client';
import PortalShell from './PortalShell';

const MCIM_ID = 'MCIM-18.6-PORTAL-SUPPORT';
const AUTHORITY = 'Portal Support Authority';
const sourceOfTruth = '/api/core/field-assessment/engagements';
const drillDown = '/support';
const customerSafe = true;

export interface SupportContext {
  engagementContact: string | null;
  contactEmail: string | null;
  nextMeeting: string | null;
  supportRequestPath: string | null;
  escalationNote: string | null;
  documentationLinks: { label: string; url: string }[];
  statusExplanations: { status: string; explanation: string }[];
}

interface Props {
  context: SupportContext | null;
  loading: boolean;
  lastUpdated?: string;
}

export default function PortalSupportContext({ context, loading, lastUpdated }: Props) {
  return (
    <PortalShell
      mcimId={MCIM_ID}
      authority={AUTHORITY}
      capability="Portal Support"
      sourceOfTruth={sourceOfTruth}
      drillDown={drillDown}
      title="Support & Contact"
      lastUpdated={lastUpdated}
    >
      <p className="text-[11px] text-muted mb-4">
        Internal Slack, admin, and operator-only details are not shown in this view.
      </p>

      {loading && (
        <div className="space-y-3" aria-busy="true">
          {[1, 2, 3].map((i) => (
            <div key={i} className="h-6 rounded bg-surface-2 animate-pulse w-3/4" />
          ))}
        </div>
      )}

      {!loading && (
        <div className="space-y-5">
          {/* Contact */}
          <section className="space-y-1">
            <h3 className="text-xs font-semibold text-muted uppercase tracking-wider">Engagement Contact</h3>
            {context?.engagementContact ? (
              <p className="text-sm text-foreground">{context.engagementContact}</p>
            ) : (
              <p className="text-sm text-muted">Contact not specified</p>
            )}
            {context?.contactEmail ? (
              <a
                href={`mailto:${context.contactEmail}`}
                className="text-sm text-primary hover:underline"
              >
                {context.contactEmail}
              </a>
            ) : null}
          </section>

          {/* Next Meeting */}
          <section className="space-y-1">
            <h3 className="text-xs font-semibold text-muted uppercase tracking-wider">Next Meeting</h3>
            <p className="text-sm text-foreground">
              {context?.nextMeeting
                ? new Date(context.nextMeeting).toLocaleString()
                : 'Not scheduled'}
            </p>
          </section>

          {/* Support Request */}
          <section className="space-y-1">
            <h3 className="text-xs font-semibold text-muted uppercase tracking-wider">Support Request</h3>
            {context?.supportRequestPath ? (
              <a
                href={context.supportRequestPath}
                target="_blank"
                rel="noopener noreferrer"
                className="text-sm text-primary hover:underline"
              >
                Submit a support request →
              </a>
            ) : (
              <p className="text-sm text-muted">Contact your engagement team</p>
            )}
          </section>

          {/* Escalation */}
          <section className="space-y-1">
            <h3 className="text-xs font-semibold text-muted uppercase tracking-wider">Escalation</h3>
            <p className="text-sm text-foreground">
              {context?.escalationNote ?? 'Contact your engagement team for escalation'}
            </p>
          </section>

          {/* Documentation Links */}
          {context?.documentationLinks && context.documentationLinks.length > 0 && (
            <section className="space-y-1.5">
              <h3 className="text-xs font-semibold text-muted uppercase tracking-wider">Documentation</h3>
              <ul className="space-y-1">
                {context.documentationLinks.map((link, i) => (
                  <li key={i}>
                    <a
                      href={link.url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-sm text-primary hover:underline"
                    >
                      {link.label} ↗
                    </a>
                  </li>
                ))}
              </ul>
            </section>
          )}

          {/* Status Glossary */}
          {context?.statusExplanations && context.statusExplanations.length > 0 && (
            <section className="space-y-2">
              <h3 className="text-xs font-semibold text-muted uppercase tracking-wider">Status Glossary</h3>
              <table className="w-full text-xs border-collapse">
                <thead>
                  <tr className="border-b border-border text-muted">
                    <th className="text-left py-1.5 pr-4 font-medium">Status</th>
                    <th className="text-left py-1.5 font-medium">Explanation</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {context.statusExplanations.map((row, i) => (
                    <tr key={i}>
                      <td className="py-1.5 pr-4 font-mono text-foreground">{row.status}</td>
                      <td className="py-1.5 text-muted">{row.explanation}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </section>
          )}
        </div>
      )}
    </PortalShell>
  );
}

void MCIM_ID; void AUTHORITY; void sourceOfTruth; void drillDown; void customerSafe;
