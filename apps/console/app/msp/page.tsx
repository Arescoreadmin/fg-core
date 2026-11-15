'use client';

/**
 * MSP-002 — MSP portfolio console (MSP operator).
 *
 * Shows only the customers Core says this MSP member may act for right now,
 * with summaries Core returned for the capabilities each customer delegated.
 * Selecting a customer calls the audited context route, which grants nothing:
 * every later request is re-checked by Core. The selected customer is kept in
 * component state for display only; it is never sent as the caller's tenant
 * and never treated as proof of access.
 */

import { useCallback, useEffect, useState } from 'react';
import Link from 'next/link';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { ConfirmDialog } from '@/components/msp/ConfirmDialog';
import { CapabilityPicker } from '@/components/msp/CapabilityPicker';
import { RelationshipHistory } from '@/components/msp/RelationshipHistory';
import {
  changeRelationship,
  getPortfolio,
  listAllRelationships,
  proposeRelationship,
  selectCustomerContext,
  type CustomerContext,
  type PortfolioItem,
  type PortfolioPage,
  type Relationship,
} from '@/lib/mspApi';
import {
  availableActions,
  buildProposalBody,
  capabilityLabel,
  nextAction,
  safeErrorMessage,
  sectionStateLabel,
  statusView,
  summarizeRelationships,
} from '@/lib/mspConsole';

const PAGE_SIZE = 25;

const INACCESSIBLE_REASON: Record<string, string> = {
  proposed: 'Waiting for the customer’s administrator to approve. You have no access until then.',
  approved: 'Approved, but the access period has not started yet.',
  suspended: 'The customer suspended access. Only the customer can resume it.',
  expired: 'The approved access period ended. Send a new request if the work continues.',
  revoked: 'This relationship has ended. Send a new request if needed.',
};

function fmtDate(iso: string | null | undefined): string {
  return iso ? new Date(iso).toLocaleDateString() : '—';
}

function AssessmentCell({ item }: { item: PortfolioItem }) {
  const a = item.assessment;
  if (a.state !== 'available') return <span className="text-muted">{sectionStateLabel(a.state)}</span>;
  const entries = Object.entries(a.engagements_by_status ?? {});
  return (
    <span>
      {entries.map(([s, n]) => `${n} ${s.replace(/_/g, ' ')}`).join(', ')}
      {a.truncated ? <span className="text-muted"> (most recent {a.observed} shown)</span> : null}
    </span>
  );
}

function FindingsCell({ item }: { item: PortfolioItem }) {
  const f = item.findings;
  if (f.state !== 'available') return <span className="text-muted">{sectionStateLabel(f.state)}</span>;
  const entries = Object.entries(f.outstanding_by_severity ?? {});
  return (
    <span>
      {f.outstanding_total ?? 0} outstanding
      {entries.length ? ` (${entries.map(([s, n]) => `${n} ${s}`).join(', ')})` : ''}
      {f.truncated ? <span className="text-muted"> — of the {f.observed} most recent</span> : null}
    </span>
  );
}

export default function MspPortfolioPage() {
  const [portfolio, setPortfolio] = useState<PortfolioPage | null>(null);
  const [relationships, setRelationships] = useState<Relationship[]>([]);
  const [offset, setOffset] = useState(0);
  const [loadError, setLoadError] = useState('');
  const [sessionExpired, setSessionExpired] = useState(false);
  const [notConfigured, setNotConfigured] = useState(false);
  const [selected, setSelected] = useState<{ item: PortfolioItem; context: CustomerContext } | null>(null);
  const [selectError, setSelectError] = useState('');
  const [selecting, setSelecting] = useState<string | null>(null);
  const [customerId, setCustomerId] = useState('');
  const [requestCaps, setRequestCaps] = useState<string[]>(['assessment.read', 'finding.read']);
  const [proposing, setProposing] = useState(false);
  const [proposeMsg, setProposeMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [revokeTarget, setRevokeTarget] = useState<Relationship | null>(null);
  const [revoking, setRevoking] = useState(false);
  const [revokeError, setRevokeError] = useState('');
  const [historyFor, setHistoryFor] = useState<string | null>(null);

  const load = useCallback(async (nextOffset: number) => {
    const [p, r] = await Promise.all([getPortfolio(PAGE_SIZE, nextOffset), listAllRelationships()]);
    for (const res of [p, r]) {
      if (!res.ok && res.status === 401) {
        setSessionExpired(true);
        return;
      }
    }
    if (!p.ok) {
      if (p.status === 403 && (p.code === 'MSP_ACCESS_DENIED' || p.code === 'MSP_ORGANIZATION_INACTIVE')) {
        setNotConfigured(true);
      }
      setLoadError(safeErrorMessage(p));
      setPortfolio({ msp_tenant_id: '', items: [], total: 0, limit: PAGE_SIZE, offset: 0, next_offset: null, generated_at: '' });
    } else {
      // A failed or incomplete relationship list is shown, never rendered as empty.
      setLoadError(r.ok ? '' : safeErrorMessage(r));
      setNotConfigured(false);
      setPortfolio(p.data);
    }
    setRelationships(r.ok ? r.data.items.filter((x) => x.party === 'msp') : []);
  }, []);

  useEffect(() => {
    void load(offset);
  }, [load, offset]);

  const openCustomer = async (item: PortfolioItem) => {
    if (selecting) return;
    setSelecting(item.customer_tenant_id);
    setSelectError('');
    const res = await selectCustomerContext(item.customer_tenant_id);
    setSelecting(null);
    if (!res.ok) {
      if (res.status === 401) setSessionExpired(true);
      setSelected(null);
      setSelectError(safeErrorMessage(res));
      await load(offset); // access may have just ended; show Core's current view
      return;
    }
    setSelected({ item, context: res.data });
  };

  const submitProposal = async () => {
    if (proposing) return;
    setProposeMsg(null);
    const built = buildProposalBody({ customerTenantId: customerId, selected: requestCaps });
    if (!built.ok) {
      setProposeMsg({ ok: false, text: built.error });
      return;
    }
    setProposing(true);
    try {
      const res = await proposeRelationship(built.body);
      if (!res.ok) {
        if (res.status === 401) setSessionExpired(true);
        setProposeMsg({
          ok: false,
          text:
            res.status === 404
              ? 'That organization cannot receive a request. Check the ID with the customer.'
              : safeErrorMessage(res),
        });
        return;
      }
      setProposeMsg({
        ok: true,
        text: res.data.created
          ? 'Request sent. The customer’s administrator must approve it before you have any access.'
          : 'This request is already waiting for the customer’s approval.',
      });
      setCustomerId('');
      await load(offset);
    } finally {
      setProposing(false);
    }
  };

  const confirmRevoke = async () => {
    if (!revokeTarget || revoking) return;
    setRevoking(true);
    setRevokeError('');
    try {
      const res = await changeRelationship(revokeTarget.relationship_id, 'revoke');
      if (!res.ok) {
        if (res.status === 401) setSessionExpired(true);
        setRevokeError(safeErrorMessage(res));
        return;
      }
      setRevokeTarget(null);
      if (selected && selected.item.relationship_id === revokeTarget.relationship_id) setSelected(null);
      await load(offset);
    } finally {
      setRevoking(false);
    }
  };

  if (sessionExpired) {
    return (
      <main className="mx-auto max-w-6xl p-6">
        <p role="alert" className="text-sm">
          Your session has expired. <Link href="/login" className="text-primary underline">Sign in again</Link> to continue.
        </p>
      </main>
    );
  }

  const counts = summarizeRelationships(relationships);
  const notActive = relationships.filter((r) => r.status !== 'active');

  return (
    <main className="mx-auto max-w-6xl space-y-6 p-6" data-testid="msp-portfolio-page">
      <header className="space-y-1">
        <h1 className="text-2xl font-semibold">MSP portfolio</h1>
        <p className="text-sm text-muted">
          Customers appear here only while they have approved your access. Everything shown is read-only and limited
          to what each customer delegated. Access is checked again on every request.
        </p>
      </header>

      {notConfigured ? (
        <Card data-testid="msp-not-configured">
          <CardContent className="p-4 text-sm">
            Your organization is not set up as an active managed service provider, or your account cannot use it.
            Contact FrostGate to enable MSP access for your organization.
          </CardContent>
        </Card>
      ) : null}
      {loadError && !notConfigured ? (
        <p role="alert" className="text-sm text-danger">
          {loadError}
        </p>
      ) : null}

      <section aria-label="Portfolio overview" className="grid grid-cols-2 gap-3 sm:grid-cols-5" data-testid="msp-overview">
        {[
          ['Authorized customers', portfolio?.total ?? 0],
          ['Active', counts.active],
          ['Awaiting approval', counts.pending],
          ['Suspended', counts.suspended],
          ['Ending within 30 days', counts.expiring],
        ].map(([label, n]) => (
          <Card key={String(label)}>
            <CardContent className="p-3">
              <p className="text-xs text-muted">{label}</p>
              <p className="text-xl font-semibold">{portfolio ? n : '…'}</p>
            </CardContent>
          </Card>
        ))}
      </section>

      <section aria-labelledby="msp-customers-h" className="space-y-3" data-testid="msp-customer-list">
        <h2 id="msp-customers-h" className="text-lg font-semibold">
          Authorized customers
        </h2>
        {portfolio === null ? (
          <p aria-live="polite" aria-label="Loading portfolio" className="text-sm text-muted">
            Loading…
          </p>
        ) : portfolio.items.length === 0 ? (
          <p className="text-sm text-muted" data-testid="msp-empty-portfolio">
            No customer has approved access yet. Send a request below; customers appear here once they approve.
          </p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <caption className="sr-only">Customers you are authorized to manage</caption>
              <thead className="text-xs text-muted">
                <tr>
                  <th scope="col" className="py-2 pr-3">Customer</th>
                  <th scope="col" className="py-2 pr-3">Delegated</th>
                  <th scope="col" className="py-2 pr-3">Assessments</th>
                  <th scope="col" className="py-2 pr-3">Findings</th>
                  <th scope="col" className="py-2 pr-3">Access ends</th>
                  <th scope="col" className="py-2"><span className="sr-only">Actions</span></th>
                </tr>
              </thead>
              <tbody>
                {portfolio.items.map((item) => (
                  <tr key={item.relationship_id} className="border-t border-border align-top">
                    <td className="py-2 pr-3 font-medium">{item.display_name || item.customer_tenant_id}</td>
                    <td className="py-2 pr-3">{item.effective_permissions.map(capabilityLabel).join(', ')}</td>
                    <td className="py-2 pr-3"><AssessmentCell item={item} /></td>
                    <td className="py-2 pr-3"><FindingsCell item={item} /></td>
                    <td className="py-2 pr-3">{fmtDate(item.expires_at)}</td>
                    <td className="py-2">
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => void openCustomer(item)}
                        loading={selecting === item.customer_tenant_id}
                        disabled={selecting !== null}
                      >
                        Open
                      </Button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {portfolio && portfolio.total > PAGE_SIZE ? (
          <nav aria-label="Portfolio pages" className="flex items-center gap-2 text-sm">
            <Button size="sm" variant="outline" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}>
              Previous
            </Button>
            <span className="text-muted">
              {offset + 1}–{offset + portfolio.items.length} of {portfolio.total}
            </span>
            <Button
              size="sm"
              variant="outline"
              disabled={portfolio.next_offset === null}
              onClick={() => portfolio.next_offset !== null && setOffset(portfolio.next_offset)}
            >
              Next
            </Button>
          </nav>
        ) : null}
        {selectError ? (
          <p role="alert" className="text-sm text-danger">
            {selectError}
          </p>
        ) : null}
      </section>

      {selected ? (
        <Card aria-live="polite" data-testid="msp-customer-detail">
          <CardHeader>
            <CardTitle className="text-base">{selected.item.display_name || selected.item.customer_tenant_id}</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2 text-sm">
            <p>
              <Badge variant="success">Active</Badge>{' '}
              <span className="text-muted">Access valid until {fmtDate(selected.context.valid_until)}; re-checked on every request.</span>
            </p>
            <p>
              <span className="font-medium">You may use:</span>{' '}
              {selected.context.effective_permissions.map(capabilityLabel).join(', ')}
            </p>
            <p><span className="font-medium">Assessments:</span> <AssessmentCell item={selected.item} /></p>
            <p><span className="font-medium">Findings:</span> <FindingsCell item={selected.item} /></p>
            <p><span className="font-medium">Next step:</span> {nextAction(selected.item)}</p>
            <div className="flex gap-2 pt-1">
              <Button size="sm" variant="ghost" onClick={() => setSelected(null)}>
                Close
              </Button>
              {(() => {
                const rel = relationships.find((r) => r.relationship_id === selected.item.relationship_id);
                return rel ? (
                  <Button size="sm" variant="outline" onClick={() => { setRevokeError(''); setRevokeTarget(rel); }}>
                    End relationship
                  </Button>
                ) : null;
              })()}
            </div>
          </CardContent>
        </Card>
      ) : null}

      <section aria-labelledby="msp-requests-h" className="space-y-3" data-testid="msp-relationship-requests">
        <h2 id="msp-requests-h" className="text-lg font-semibold">
          Your requests and ended relationships
        </h2>
        {notActive.length === 0 ? (
          <p className="text-sm text-muted">Nothing pending or ended.</p>
        ) : (
          notActive.map((rel) => {
            const status = statusView(rel.status);
            return (
              <Card key={rel.relationship_id}>
                <CardContent className="space-y-2 p-4 text-sm">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <span className="font-medium">{rel.counterparty_display_name || rel.customer_tenant_id}</span>
                    <Badge variant={status.tone}>{status.label}</Badge>
                  </div>
                  <p className="text-muted">{INACCESSIBLE_REASON[rel.status] ?? 'Not currently accessible.'}</p>
                  <p className="text-xs text-muted">Requested: {rel.requested_capabilities.map(capabilityLabel).join(', ')}</p>
                  <div className="flex gap-2">
                    {availableActions(rel, 'msp').includes('revoke') ? (
                      <Button size="sm" variant="outline" onClick={() => { setRevokeError(''); setRevokeTarget(rel); }}>
                        {rel.status === 'proposed' ? 'Withdraw request' : 'End relationship'}
                      </Button>
                    ) : null}
                    <Button
                      size="sm"
                      variant="ghost"
                      aria-expanded={historyFor === rel.relationship_id}
                      onClick={() => setHistoryFor(historyFor === rel.relationship_id ? null : rel.relationship_id)}
                    >
                      {historyFor === rel.relationship_id ? 'Hide history' : 'View history'}
                    </Button>
                  </div>
                  {historyFor === rel.relationship_id ? <RelationshipHistory relationshipId={rel.relationship_id} /> : null}
                </CardContent>
              </Card>
            );
          })
        )}
      </section>

      <section aria-labelledby="msp-propose-h" className="space-y-3" data-testid="msp-propose">
        <h2 id="msp-propose-h" className="text-lg font-semibold">
          Request access to a customer
        </h2>
        <p className="text-sm text-muted">
          The customer’s own administrator must approve. They can approve fewer capabilities than you request, choose
          how long access lasts (at most a year), and suspend or revoke it at any time. You cannot approve your own
          request.
        </p>
        <form
          className="space-y-3"
          onSubmit={(e) => {
            e.preventDefault();
            void submitProposal();
          }}
        >
          <div className="space-y-1">
            <label htmlFor="msp-customer-id" className="text-sm font-medium">
              Customer organization ID
            </label>
            <input
              id="msp-customer-id"
              value={customerId}
              onChange={(e) => setCustomerId(e.target.value)}
              disabled={proposing}
              autoComplete="off"
              aria-describedby="msp-customer-id-help"
              className="h-9 w-full max-w-sm rounded border border-border bg-surface-2 px-2 text-sm"
            />
            <p id="msp-customer-id-help" className="text-xs text-muted">
              The customer’s administrator finds this on their Managed service partners page.
            </p>
          </div>
          <CapabilityPicker legend="Capabilities to request" selected={requestCaps} onChange={setRequestCaps} disabled={proposing} />
          <Button type="submit" loading={proposing} aria-busy={proposing}>
            Send request
          </Button>
          {proposeMsg ? (
            <p role={proposeMsg.ok ? 'status' : 'alert'} className={proposeMsg.ok ? 'text-sm text-success' : 'text-sm text-danger'}>
              {proposeMsg.text}
            </p>
          ) : null}
        </form>
      </section>

      <ConfirmDialog
        open={revokeTarget !== null}
        title={revokeTarget?.status === 'proposed' ? 'Withdraw this request?' : 'End this relationship?'}
        description="Your access ends immediately and cannot be restored; you would need to send a new request. The customer's records are not changed."
        confirmLabel={revokeTarget?.status === 'proposed' ? 'Withdraw request' : 'End relationship'}
        destructive
        busy={revoking}
        onCancel={() => setRevokeTarget(null)}
        onConfirm={() => void confirmRevoke()}
      >
        {revokeError ? (
          <p role="alert" className="text-sm text-danger">
            {revokeError}
          </p>
        ) : null}
      </ConfirmDialog>
    </main>
  );
}
