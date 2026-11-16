'use client';

/**
 * MSP-007 — customer-controlled report sharing (customer view, /partners).
 *
 * The customer's own administrator sees each report version with every
 * lifecycle fact kept separate (generated, QA approved, independent QA,
 * qualified, released, delivery authorized, delivered) and its integrity,
 * shares one exact released version with one partner for a bounded time,
 * answers partner requests, revokes access, and reads who accessed what.
 *
 * Renders nothing for an organization with no partner that has report access
 * and no shares, so direct customers see no MSP controls. Every action only
 * asks Core (api/msp_reporting.py), which re-checks release, integrity and the
 * relationship; the lists reload after each action.
 */

import { useCallback, useEffect, useMemo, useState } from 'react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';
import { ConfirmDialog } from '@/components/msp/ConfirmDialog';
import { ShareHistory } from '@/components/msp/ShareHistory';
import {
  decideReportShare,
  listAllRelationships,
  listAllReportShares,
  listAllShareableReports,
  shareReport,
  type Relationship,
  type ReportShare,
  type ShareableReport,
} from '@/lib/mspApi';
import {
  DEFAULT_SHARE_DAYS,
  MAX_SHARE_DAYS,
  blockerLabel,
  buildApprovalBody,
  buildShareBody,
  integrityView,
  lifecycleFacts,
  newShareKey,
  nextActionLabel,
  safeReportingError,
  shareActions,
  shareStatusView,
  shortHash,
} from '@/lib/mspReporting';

type Pending =
  | { kind: 'share'; report: ShareableReport; relationship: Relationship }
  | { kind: 'approve'; share: ReportShare; report: ShareableReport }
  | { kind: 'reject' | 'revoke'; share: ReportShare };

function fmtDate(iso: string | null | undefined): string {
  return iso ? new Date(iso).toLocaleDateString() : '—';
}

function partnerName(rels: Relationship[], relationshipId: string, fallback: string): string {
  const rel = rels.find((r) => r.relationship_id === relationshipId);
  return rel?.counterparty_display_name || fallback;
}

export function ReportSharing({ onSessionExpired }: { onSessionExpired?: () => void }) {
  const [relationships, setRelationships] = useState<Relationship[] | null>(null);
  const [shares, setShares] = useState<ReportShare[]>([]);
  const [reports, setReports] = useState<ShareableReport[]>([]);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [actionError, setActionError] = useState('');
  const [pending, setPending] = useState<Pending | null>(null);
  const [relationshipId, setRelationshipId] = useState('');
  const [reportId, setReportId] = useState('');
  const [days, setDays] = useState(DEFAULT_SHARE_DAYS);
  const [requestKey, setRequestKey] = useState(() => newShareKey());
  const [approvalReport, setApprovalReport] = useState<Record<string, string>>({});
  const [historyFor, setHistoryFor] = useState<string | null>(null);
  const [message, setMessage] = useState<{ ok: boolean; text: string } | null>(null);

  const fail = useCallback(
    (res: { ok: false; status?: number; code?: string; blockers?: string[] }) => {
      if (res.status === 401) onSessionExpired?.();
      return safeReportingError(res);
    },
    [onSessionExpired],
  );

  const load = useCallback(async () => {
    const [relRes, shareRes, reportRes] = await Promise.all([
      listAllRelationships(),
      listAllReportShares('customer'),
      listAllShareableReports(),
    ]);
    // Fail closed: if any list is incomplete, show none of it as complete.
    if (!relRes.ok || !shareRes.ok || !reportRes.ok) {
      const bad = [relRes, shareRes, reportRes].find((r) => !r.ok) as {
        ok: false;
        status?: number;
        code?: string;
      };
      setError(fail(bad));
      setRelationships([]);
      setShares([]);
      setReports([]);
      return;
    }
    setError('');
    setRelationships(
      relRes.data.items.filter(
        (r) => r.party === 'customer' && r.status === 'active' && r.authorized_capabilities.includes('report.read'),
      ),
    );
    setShares(shareRes.data.items);
    setReports(reportRes.data.items);
  }, [fail]);

  useEffect(() => {
    void load();
  }, [load]);

  const eligible = useMemo(() => reports.filter((r) => r.share_eligible), [reports]);
  const requests = shares.filter((s) => s.status === 'requested');
  const decided = shares.filter((s) => s.status !== 'requested');

  if (relationships !== null && relationships.length === 0 && shares.length === 0 && !error) return null;

  const run = async (fn: () => Promise<{ ok: boolean } & Record<string, unknown>>, okText: string) => {
    setBusy(true);
    setActionError('');
    try {
      const res = await fn();
      if (!res.ok) {
        setActionError(fail(res as { ok: false; status?: number; code?: string; blockers?: string[] }));
        await load();
        return;
      }
      setPending(null);
      setMessage({ ok: true, text: okText });
      setRequestKey(newShareKey());
      await load();
    } finally {
      setBusy(false);
    }
  };

  const confirm = async () => {
    if (!pending || busy) return;
    if (pending.kind === 'share') {
      const built = buildShareBody({
        relationshipId: pending.relationship.relationship_id,
        report: pending.report,
        days,
        requestKey,
      });
      if (!built.ok) {
        setActionError(built.error);
        return;
      }
      await run(() => shareReport(built.body), 'Report shared. You can revoke access at any time.');
    } else if (pending.kind === 'approve') {
      const built = buildApprovalBody({ report: pending.report, days });
      if (!built.ok) {
        setActionError(built.error);
        return;
      }
      await run(
        () => decideReportShare(pending.share.share_id, 'approve', pending.share.version, built.body),
        'Report shared with your partner.',
      );
    } else {
      await run(
        () => decideReportShare(pending.share.share_id, pending.kind, pending.share.version),
        pending.kind === 'revoke' ? 'Access revoked. Your partner can no longer open this report.' : 'Request declined.',
      );
    }
  };

  const startShare = () => {
    setMessage(null);
    const relationship = (relationships ?? []).find((r) => r.relationship_id === relationshipId);
    const report = eligible.find((r) => r.report_id === reportId);
    if (!relationship || !report) {
      setMessage({ ok: false, text: 'Choose a partner and a released report.' });
      return;
    }
    setActionError('');
    setPending({ kind: 'share', report, relationship });
  };

  const pendingText = (): { title: string; description: string; label: string; destructive: boolean } => {
    if (!pending) return { title: '', description: '', label: '', destructive: false };
    if (pending.kind === 'share' || pending.kind === 'approve') {
      const who =
        pending.kind === 'share'
          ? pending.relationship.counterparty_display_name || pending.relationship.msp_tenant_id
          : partnerName(relationships ?? [], pending.share.relationship_id, pending.share.msp_tenant_id);
      return {
        title: `Share report v${pending.report.version} with ${who}?`,
        description: `Only this version (fingerprint ${shortHash(pending.report.manifest_hash)}) is shared, for ${days} days. Your partner can view and download it; every access is recorded here. You can revoke future access at any time, but a copy already downloaded cannot be recalled.`,
        label: 'Share report',
        destructive: false,
      };
    }
    if (pending.kind === 'revoke') {
      return {
        title: 'Revoke access to this report?',
        description: 'Your partner can no longer open or download it. The history of past access is kept.',
        label: 'Revoke',
        destructive: true,
      };
    }
    return {
      title: 'Decline this request?',
      description: 'Your partner will not receive this report. It can send a new request.',
      label: 'Decline',
      destructive: true,
    };
  };
  const text = pendingText();

  return (
    <section aria-labelledby="report-sharing-h" className="space-y-4" data-testid="msp-report-sharing">
      <h2 id="report-sharing-h" className="text-lg font-semibold">
        Reports shared with your partners
      </h2>
      <p className="text-sm text-muted">
        Your reports stay yours. A partner sees a report only after you share one exact released version, for a period
        you choose. Drafts and reports that are not released or did not verify cannot be shared.
      </p>
      {error ? (
        <p role="alert" className="text-sm text-danger">
          {error}
        </p>
      ) : null}
      {relationships === null ? (
        <p aria-live="polite" className="text-sm text-muted">
          Loading…
        </p>
      ) : null}

      {requests.length > 0 ? (
        <div className="space-y-2" data-testid="msp-report-requests">
          <h3 className="text-sm font-semibold">Requests from your partners</h3>
          {requests.map((s) => {
            const candidates = eligible.filter((r) => r.engagement_id === s.engagement_id);
            const chosen = candidates.find((r) => r.report_id === approvalReport[s.share_id]) ?? null;
            return (
              <Card key={s.share_id} data-testid="msp-report-request-item">
                <CardContent className="space-y-2 p-4 text-sm">
                  <p className="font-medium">
                    {partnerName(relationships ?? [], s.relationship_id, s.msp_tenant_id)} asks for the report of
                    engagement {s.engagement_id}
                  </p>
                  {candidates.length === 0 ? (
                    <p className="text-xs text-muted">No released version of this engagement’s report exists yet.</p>
                  ) : (
                    <label className="block space-y-1 text-xs">
                      <span className="font-medium">Version to share</span>
                      <select
                        value={approvalReport[s.share_id] ?? ''}
                        onChange={(e) => setApprovalReport({ ...approvalReport, [s.share_id]: e.target.value })}
                        disabled={busy}
                        className="h-9 rounded border border-border bg-surface-2 px-2"
                      >
                        <option value="">Choose a version</option>
                        {candidates.map((r) => (
                          <option key={r.report_id} value={r.report_id}>
                            v{r.version} · {shortHash(r.manifest_hash)}
                          </option>
                        ))}
                      </select>
                    </label>
                  )}
                  <div className="flex gap-2">
                    <Button
                      size="sm"
                      disabled={busy || chosen === null}
                      onClick={() => chosen && setPending({ kind: 'approve', share: s, report: chosen })}
                    >
                      Share this version
                    </Button>
                    <Button size="sm" variant="outline" disabled={busy} onClick={() => setPending({ kind: 'reject', share: s })}>
                      Decline
                    </Button>
                  </div>
                </CardContent>
              </Card>
            );
          })}
        </div>
      ) : null}

      {(relationships ?? []).length > 0 ? (
        <form
          className="space-y-3"
          data-testid="msp-report-share-form"
          onSubmit={(e) => {
            e.preventDefault();
            startShare();
          }}
        >
          <h3 className="text-sm font-semibold">Share a report</h3>
          <div className="flex flex-wrap gap-3">
            <label className="space-y-1 text-sm">
              <span className="block font-medium">Partner</span>
              <select
                value={relationshipId}
                onChange={(e) => setRelationshipId(e.target.value)}
                disabled={busy}
                className="h-9 rounded border border-border bg-surface-2 px-2"
              >
                <option value="">Choose a partner</option>
                {(relationships ?? []).map((r) => (
                  <option key={r.relationship_id} value={r.relationship_id}>
                    {r.counterparty_display_name || r.msp_tenant_id}
                  </option>
                ))}
              </select>
            </label>
            <label className="space-y-1 text-sm">
              <span className="block font-medium">Released report</span>
              <select
                value={reportId}
                onChange={(e) => setReportId(e.target.value)}
                disabled={busy || eligible.length === 0}
                className="h-9 rounded border border-border bg-surface-2 px-2"
              >
                <option value="">{eligible.length === 0 ? 'No released report yet' : 'Choose a report'}</option>
                {eligible.map((r) => (
                  <option key={r.report_id} value={r.report_id}>
                    Engagement {r.engagement_id} · v{r.version} · {shortHash(r.manifest_hash)}
                  </option>
                ))}
              </select>
            </label>
            <label className="space-y-1 text-sm">
              <span className="block font-medium">Days</span>
              <input
                type="number"
                min={1}
                max={MAX_SHARE_DAYS}
                value={days}
                onChange={(e) => setDays(Number(e.target.value))}
                disabled={busy}
                className="h-9 w-20 rounded border border-border bg-surface-2 px-2"
              />
            </label>
          </div>
          <Button type="submit" size="sm" disabled={busy}>
            Review and share
          </Button>
        </form>
      ) : null}

      {decided.length > 0 ? (
        <div className="space-y-2" data-testid="msp-report-shares">
          <h3 className="text-sm font-semibold">Shared reports</h3>
          {decided.map((s) => {
            const status = shareStatusView(s);
            const actions = shareActions(s);
            return (
              <Card key={s.share_id} data-testid="msp-report-share">
                <CardContent className="space-y-2 p-4 text-sm">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <span className="font-medium">
                      {s.report_version !== null ? `Report v${s.report_version}` : 'Report'} · engagement {s.engagement_id} ·{' '}
                      {partnerName(relationships ?? [], s.relationship_id, s.msp_tenant_id)}
                    </span>
                    <Badge variant={status.tone}>{status.label}</Badge>
                  </div>
                  <p className="text-xs text-muted">
                    Fingerprint <code>{shortHash(s.manifest_hash)}</code> · until {fmtDate(s.expires_at)}
                  </p>
                  {s.next_actions.length > 0 ? (
                    <p className="text-xs">
                      <span className="font-medium">Next:</span> {s.next_actions.map(nextActionLabel).join('; ')}
                    </p>
                  ) : null}
                  <div className="flex gap-2">
                    {actions.includes('revoke') ? (
                      <Button size="sm" variant="outline" disabled={busy} onClick={() => setPending({ kind: 'revoke', share: s })}>
                        Revoke
                      </Button>
                    ) : null}
                    <Button size="sm" variant="ghost" onClick={() => setHistoryFor(historyFor === s.share_id ? null : s.share_id)}>
                      {historyFor === s.share_id ? 'Hide access history' : 'Access history'}
                    </Button>
                  </div>
                  {historyFor === s.share_id ? <ShareHistory shareId={s.share_id} /> : null}
                </CardContent>
              </Card>
            );
          })}
        </div>
      ) : null}

      {reports.length > 0 ? (
        <details className="space-y-2" data-testid="msp-report-index">
          <summary className="cursor-pointer text-sm font-semibold">Your reports and their status</summary>
          {reports.map((r) => (
            <Card key={r.report_id}>
              <CardContent className="space-y-1 p-4 text-xs">
                <p className="text-sm font-medium">
                  Engagement {r.engagement_id} · v{r.version} · <code>{shortHash(r.manifest_hash)}</code>
                </p>
                <ul className="flex flex-wrap gap-2" aria-label="Report lifecycle">
                  {lifecycleFacts(r.lifecycle as unknown as Record<string, unknown>).map((f) => (
                    <li key={f.id}>
                      <Badge variant={f.value ? 'success' : 'outline'}>
                        {f.label}: {f.value ? 'yes' : 'no'}
                      </Badge>
                    </li>
                  ))}
                </ul>
                <p>
                  Content: {integrityView(r.integrity.content).label} · Signature: {integrityView(r.integrity.signature).label}
                </p>
                {r.share_blockers.length > 0 ? (
                  <p className="text-muted">Cannot be shared: {r.share_blockers.map(blockerLabel).join(' ')}</p>
                ) : null}
              </CardContent>
            </Card>
          ))}
        </details>
      ) : null}

      {message ? (
        <p role={message.ok ? 'status' : 'alert'} className={message.ok ? 'text-sm text-success' : 'text-sm text-danger'}>
          {message.text}
        </p>
      ) : null}

      <ConfirmDialog
        open={pending !== null}
        title={text.title}
        description={text.description}
        confirmLabel={text.label}
        destructive={text.destructive}
        busy={busy}
        onCancel={() => setPending(null)}
        onConfirm={() => void confirm()}
      >
        {actionError ? (
          <p role="alert" className="text-sm text-danger">
            {actionError}
          </p>
        ) : null}
      </ConfirmDialog>
    </section>
  );
}
