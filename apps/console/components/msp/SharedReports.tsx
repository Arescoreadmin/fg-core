'use client';

/**
 * MSP-007 — partner managed reporting for ONE selected customer (MSP view).
 *
 * Lists only the reports that customer explicitly shared, grouped by whether
 * they can be read now, with the exact version and fingerprint, expiry, and
 * Core's reasons when a report is unavailable. Verify and download re-check
 * the share in Core on every call; nothing here is cached across customers
 * (the parent keys this component by customer, so switching customers
 * discards every list, summary and selection).
 *
 * The MSP can also ask for the report of an assessment it started under an
 * MSP-003 grant. Asking grants nothing; the customer chooses whether, which
 * version and for how long. No metric here is computed by the browser.
 */

import { useCallback, useEffect, useState } from 'react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';
import { ShareHistory } from '@/components/msp/ShareHistory';
import {
  decideReportShare,
  downloadSharedReport,
  listAllAssessmentGrants,
  listAllReportShares,
  requestReportShare,
  verifySharedReport,
  type AssessmentGrant,
  type ReportShare,
  type SharedReportSummary,
} from '@/lib/mspApi';
import {
  blockerLabel,
  downloadFilename,
  groupShares,
  integrityView,
  lifecycleFacts,
  newShareKey,
  nextActionLabel,
  safeReportingError,
  shareActions,
  shareStatusView,
  shortHash,
  signatureKindLabel,
} from '@/lib/mspReporting';

interface Props {
  /** The selected customer. A display filter, never authority. */
  customerTenantId: string;
  onSessionExpired?: () => void;
}

function fmtDate(iso: string | null | undefined): string {
  return iso ? new Date(iso).toLocaleDateString() : '—';
}

export function SharedReports({ customerTenantId, onSessionExpired }: Props) {
  const [shares, setShares] = useState<ReportShare[] | null>(null);
  const [grants, setGrants] = useState<AssessmentGrant[]>([]);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<{ ok: boolean; text: string } | null>(null);
  const [summary, setSummary] = useState<SharedReportSummary | null>(null);
  const [historyFor, setHistoryFor] = useState<string | null>(null);

  const fail = useCallback(
    (res: { ok: false; status?: number; code?: string; blockers?: string[] }) => {
      if (res.status === 401) onSessionExpired?.();
      return safeReportingError(res);
    },
    [onSessionExpired],
  );

  const load = useCallback(async () => {
    const [res, grantRes] = await Promise.all([
      listAllReportShares('msp', customerTenantId),
      listAllAssessmentGrants(customerTenantId),
    ]);
    if (!res.ok) {
      setError(fail(res));
      setShares([]);
      return;
    }
    setError('');
    // Defence in depth: never show a row for another customer.
    setShares(res.data.items.filter((s) => s.customer_tenant_id === customerTenantId));
    setGrants(
      grantRes.ok
        ? grantRes.data.items.filter(
            (g) => g.party === 'msp' && g.customer_tenant_id === customerTenantId && g.status === 'initiated',
          )
        : [],
    );
  }, [customerTenantId, fail]);

  useEffect(() => {
    void load();
  }, [load]);

  const verify = async (share: ReportShare) => {
    if (busy) return;
    setBusy(true);
    setMessage(null);
    setSummary(null);
    try {
      const res = await verifySharedReport(share.share_id);
      if (!res.ok) {
        setMessage({ ok: false, text: fail(res) });
      } else if (res.data.customer_tenant_id === customerTenantId) {
        setSummary(res.data);
      }
      await load();
    } finally {
      setBusy(false);
    }
  };

  const download = async (share: ReportShare) => {
    if (busy) return;
    setBusy(true);
    setMessage(null);
    try {
      const res = await downloadSharedReport(share.share_id);
      if (!res.ok) {
        setMessage({ ok: false, text: fail(res) });
        await load();
        return;
      }
      const blob = new Blob([JSON.stringify(res.data, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = downloadFilename(res.data as { engagement_id?: unknown; version?: unknown });
      a.click();
      URL.revokeObjectURL(url);
      setMessage({ ok: true, text: 'Report downloaded. The customer can see this download in its history.' });
    } finally {
      setBusy(false);
    }
  };

  const withdraw = async (share: ReportShare) => {
    if (busy) return;
    setBusy(true);
    try {
      const res = await decideReportShare(share.share_id, 'withdraw', share.version);
      if (!res.ok) setMessage({ ok: false, text: fail(res) });
      await load();
    } finally {
      setBusy(false);
    }
  };

  const ask = async (grant: AssessmentGrant) => {
    if (busy) return;
    setBusy(true);
    setMessage(null);
    try {
      const res = await requestReportShare({ grant_id: grant.grant_id, request_key: newShareKey('rpt') });
      setMessage(
        res.ok
          ? { ok: true, text: 'Request sent. The customer chooses whether to share, which version, and for how long.' }
          : { ok: false, text: fail(res) },
      );
      await load();
    } finally {
      setBusy(false);
    }
  };

  const requested = new Set((shares ?? []).filter((s) => s.status === 'requested').map((s) => s.grant_id));
  const askable = grants.filter((g) => !requested.has(g.grant_id));

  return (
    <section aria-labelledby="msp-shared-reports-h" className="space-y-3" data-testid="msp-shared-reports">
      <h2 id="msp-shared-reports-h" className="text-lg font-semibold">
        Reports shared by this customer
      </h2>
      <p className="text-sm text-muted">
        You see only report versions this customer chose to share with you, until the date it set. It can revoke access
        at any time. Every view and download is recorded in the customer’s history.
      </p>
      {error ? (
        <p role="alert" className="text-sm text-danger">
          {error}
        </p>
      ) : null}
      {shares === null ? (
        <p aria-live="polite" className="text-sm text-muted">
          Loading…
        </p>
      ) : shares.length === 0 && !error ? (
        <p className="text-sm text-muted">This customer has not shared any reports with you.</p>
      ) : (
        groupShares(shares).map((group) =>
          group.items.length === 0 ? null : (
            <div key={group.id} className="space-y-2" data-testid={`msp-shared-group-${group.id}`}>
              <h3 className="text-sm font-semibold">
                {group.title} ({group.items.length})
              </h3>
              {group.items.map((s) => {
                const status = shareStatusView(s);
                const actions = shareActions(s);
                return (
                  <Card key={s.share_id} data-testid="msp-shared-report">
                    <CardContent className="space-y-2 p-4 text-sm">
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <span className="font-medium">
                          {s.report_version !== null ? `Report v${s.report_version}` : 'Report requested'} · engagement{' '}
                          {s.engagement_id}
                        </span>
                        <Badge variant={status.tone}>{status.label}</Badge>
                      </div>
                      <p className="text-xs text-muted">
                        Fingerprint <code>{shortHash(s.manifest_hash)}</code> · shared until {fmtDate(s.expires_at)}
                      </p>
                      {s.access && s.access.blockers.length > 0 ? (
                        <ul className="list-disc pl-5 text-xs text-muted" aria-label="Why this report is not available">
                          {s.access.blockers.map((b) => (
                            <li key={b}>{blockerLabel(b)}</li>
                          ))}
                        </ul>
                      ) : null}
                      {s.next_actions.length > 0 ? (
                        <p className="text-xs">
                          <span className="font-medium">Next:</span> {s.next_actions.map(nextActionLabel).join('; ')}
                        </p>
                      ) : null}
                      <div className="flex flex-wrap gap-2">
                        {actions.includes('verify') ? (
                          <Button size="sm" variant="outline" disabled={busy} onClick={() => void verify(s)}>
                            Verify
                          </Button>
                        ) : null}
                        {actions.includes('download') ? (
                          <Button size="sm" disabled={busy} onClick={() => void download(s)}>
                            Download
                          </Button>
                        ) : null}
                        {actions.includes('withdraw') ? (
                          <Button size="sm" variant="outline" disabled={busy} onClick={() => void withdraw(s)}>
                            Withdraw request
                          </Button>
                        ) : null}
                        <Button
                          size="sm"
                          variant="ghost"
                          onClick={() => setHistoryFor(historyFor === s.share_id ? null : s.share_id)}
                        >
                          {historyFor === s.share_id ? 'Hide history' : 'History'}
                        </Button>
                      </div>
                      {historyFor === s.share_id ? <ShareHistory shareId={s.share_id} /> : null}
                    </CardContent>
                  </Card>
                );
              })}
            </div>
          ),
        )
      )}

      {summary ? (
        <Card data-testid="msp-shared-report-summary">
          <CardContent className="space-y-2 p-4 text-sm">
            <p className="font-medium">
              Verified report v{summary.version} · {new Date(summary.verified_at).toLocaleString()}
            </p>
            <ul className="grid gap-1 text-xs sm:grid-cols-2">
              <li>
                Content: <Badge variant={integrityView(summary.integrity.content).tone}>{integrityView(summary.integrity.content).label}</Badge>
              </li>
              <li>
                Signature ({signatureKindLabel(summary.integrity.signature_kind)}):{' '}
                <Badge variant={integrityView(summary.integrity.signature).tone}>{integrityView(summary.integrity.signature).label}</Badge>
              </li>
              <li>
                Evidence chain:{' '}
                <Badge variant={integrityView(summary.integrity.evidence_chain).tone}>
                  {integrityView(summary.integrity.evidence_chain).label}
                </Badge>
              </li>
              <li>
                Fingerprint <code>{shortHash(summary.manifest_hash)}</code>
              </li>
            </ul>
            <ul className="flex flex-wrap gap-2 text-xs" aria-label="Report lifecycle">
              {lifecycleFacts(summary.lifecycle as unknown as Record<string, unknown>).map((f) => (
                <li key={f.id}>
                  <Badge variant={f.value ? 'success' : 'outline'}>
                    {f.label}: {f.value ? 'yes' : 'no'}
                  </Badge>
                </li>
              ))}
            </ul>
            <p className="text-xs text-muted">
              {summary.evidence_references.count} evidence references (identifiers only; evidence content is not shared).
            </p>
          </CardContent>
        </Card>
      ) : null}

      {askable.length > 0 ? (
        <div className="space-y-2 border-t border-border pt-3" data-testid="msp-report-request">
          <h3 className="text-sm font-semibold">Ask for a report</h3>
          <p className="text-xs text-muted">
            For assessments you started with this customer’s approval. The customer decides whether to share.
          </p>
          {askable.map((g) => (
            <div key={g.grant_id} className="flex flex-wrap items-center gap-2 text-sm">
              <span>Engagement {g.engagement_id}</span>
              <Button size="sm" variant="outline" disabled={busy} onClick={() => void ask(g)}>
                Ask the customer to share its report
              </Button>
            </div>
          ))}
        </div>
      ) : null}

      {message ? (
        <p role={message.ok ? 'status' : 'alert'} className={message.ok ? 'text-sm text-success' : 'text-sm text-danger'}>
          {message.text}
        </p>
      ) : null}
    </section>
  );
}
