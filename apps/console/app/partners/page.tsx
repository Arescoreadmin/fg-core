'use client';

/**
 * MSP-002 — Managed service partners (customer approval console).
 *
 * A customer organization's tenant_admin reviews MSP requests and approves,
 * suspends, resumes or revokes MSP access. Every action calls MSP-001's
 * relationship routes through the BFF; Core decides who may act (customer
 * tenant_admin only, never an MSP member), enforces the delegation ceiling
 * and expiry limits, and applies compare-and-set on every transition. This
 * page holds no authority: it re-reads Core after every change.
 */

import { useCallback, useEffect, useState } from 'react';
import Link from 'next/link';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { ConfirmDialog } from '@/components/msp/ConfirmDialog';
import { CapabilityPicker } from '@/components/msp/CapabilityPicker';
import { AssessmentGrants } from '@/components/msp/AssessmentGrants';
import { RelationshipHistory } from '@/components/msp/RelationshipHistory';
import {
  approveRelationship,
  changeRelationship,
  listAllRelationships,
  type LifecycleAction,
  type Relationship,
} from '@/lib/mspApi';
import {
  DEFAULT_APPROVAL_DAYS,
  MAX_RELATIONSHIP_DAYS,
  availableActions,
  buildApprovalBody,
  capabilityLabel,
  safeErrorMessage,
  statusView,
} from '@/lib/mspConsole';

type Pending =
  | { kind: 'approve'; rel: Relationship }
  | { kind: LifecycleAction; rel: Relationship }
  | null;

const ACTION_COPY: Record<LifecycleAction, { title: string; body: string; confirm: string; destructive: boolean }> = {
  suspend: {
    title: 'Suspend MSP access?',
    body: 'The MSP loses access on its next request. You can resume it later within the approved period.',
    confirm: 'Suspend access',
    destructive: true,
  },
  resume: {
    title: 'Resume MSP access?',
    body: 'The original approval and its end date apply again. An expired approval stays expired.',
    confirm: 'Resume access',
    destructive: false,
  },
  revoke: {
    title: 'Revoke MSP access permanently?',
    body: 'This ends the relationship. It cannot be undone; the MSP would have to send a new request. Your records and audit history are not changed.',
    confirm: 'Revoke access',
    destructive: true,
  },
};

function fmtDate(iso: string | null): string {
  return iso ? new Date(iso).toLocaleDateString() : '—';
}

export default function PartnersPage() {
  const [items, setItems] = useState<Relationship[] | null>(null);
  const [ownTenant, setOwnTenant] = useState('');
  const [loadError, setLoadError] = useState('');
  const [sessionExpired, setSessionExpired] = useState(false);
  const [pending, setPending] = useState<Pending>(null);
  const [busy, setBusy] = useState(false);
  const [actionError, setActionError] = useState('');
  const [notice, setNotice] = useState('');
  const [selected, setSelected] = useState<string[]>([]);
  const [days, setDays] = useState(DEFAULT_APPROVAL_DAYS);
  const [historyFor, setHistoryFor] = useState<string | null>(null);

  const load = useCallback(async () => {
    const res = await listAllRelationships();
    if (!res.ok) {
      if (res.status === 401) setSessionExpired(true);
      setLoadError(safeErrorMessage(res));
      setItems([]);
      return;
    }
    setLoadError('');
    setOwnTenant(res.data.tenant_id);
    setItems(res.data.items.filter((r) => r.party === 'customer'));
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const openAction = (kind: 'approve' | LifecycleAction, rel: Relationship) => {
    setActionError('');
    setNotice('');
    if (kind === 'approve') {
      setSelected(rel.requested_capabilities);
      setDays(DEFAULT_APPROVAL_DAYS);
    }
    setPending({ kind, rel } as Pending);
  };

  const confirm = async () => {
    if (!pending || busy) return;
    setBusy(true);
    setActionError('');
    try {
      let res;
      if (pending.kind === 'approve') {
        const built = buildApprovalBody({
          requested: pending.rel.requested_capabilities,
          selected,
          days,
        });
        if (!built.ok) {
          setActionError(built.error);
          return;
        }
        res = await approveRelationship(pending.rel.relationship_id, built.body);
      } else {
        res = await changeRelationship(pending.rel.relationship_id, pending.kind);
      }
      if (!res.ok) {
        if (res.status === 401) setSessionExpired(true);
        setActionError(safeErrorMessage(res));
        if (res.status === 409) await load();
        return;
      }
      setNotice('Saved. The MSP sees this change on its next request.');
      setPending(null);
      await load();
    } finally {
      setBusy(false);
    }
  };

  if (sessionExpired) {
    return (
      <main className="mx-auto max-w-4xl p-6">
        <p role="alert" className="text-sm">
          Your session has expired. <Link href="/login" className="text-primary underline">Sign in again</Link> to continue.
        </p>
      </main>
    );
  }

  const groups = {
    requests: (items ?? []).filter((r) => r.status === 'proposed'),
    current: (items ?? []).filter((r) => ['active', 'approved', 'suspended', 'expired'].includes(r.status)),
    ended: (items ?? []).filter((r) => r.status === 'revoked'),
  };

  const renderCard = (rel: Relationship) => {
    const status = statusView(rel.status);
    const actions = availableActions(rel, 'customer');
    const msp = rel.counterparty_display_name || 'Managed service provider';
    return (
      <Card key={rel.relationship_id} data-testid="msp-relationship-card">
        <CardHeader>
          <div className="flex flex-wrap items-center justify-between gap-2">
            <CardTitle className="text-base">{msp}</CardTitle>
            <Badge variant={status.tone}>{status.label}</Badge>
          </div>
        </CardHeader>
        <CardContent className="space-y-3 text-sm">
          <div>
            <p className="font-medium">Requested</p>
            <ul className="list-disc pl-5 text-muted">
              {rel.requested_capabilities.map((c) => (
                <li key={c}>{capabilityLabel(c)}</li>
              ))}
            </ul>
          </div>
          {rel.authorized_capabilities.length > 0 ? (
            <div>
              <p className="font-medium">You approved</p>
              <ul className="list-disc pl-5 text-muted">
                {rel.authorized_capabilities.map((c) => (
                  <li key={c}>{capabilityLabel(c)}</li>
                ))}
              </ul>
              <p className="mt-1 text-xs text-muted">
                In effect {fmtDate(rel.effective_at)} — ends {fmtDate(rel.expires_at)}
              </p>
            </div>
          ) : null}
          <div className="flex flex-wrap gap-2">
            {actions.map((a) => (
              <Button
                key={a}
                size="sm"
                variant={a === 'revoke' || a === 'suspend' ? 'outline' : 'default'}
                onClick={() => openAction(a, rel)}
                disabled={busy}
              >
                {a === 'approve' ? 'Review and approve' : a.charAt(0).toUpperCase() + a.slice(1)}
              </Button>
            ))}
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
  };

  const section = (title: string, list: Relationship[], empty: string, testId: string) => (
    <section aria-labelledby={`${testId}-h`} className="space-y-3" data-testid={testId}>
      <h2 id={`${testId}-h`} className="text-lg font-semibold">
        {title} <span className="text-sm font-normal text-muted">({list.length})</span>
      </h2>
      {list.length === 0 ? <p className="text-sm text-muted">{empty}</p> : list.map(renderCard)}
    </section>
  );

  return (
    <main className="mx-auto max-w-4xl space-y-6 p-6" data-testid="msp-partners-page">
      <header className="space-y-2">
        <h1 className="text-2xl font-semibold">Managed service partners</h1>
        <p className="text-sm text-muted">
          A managed service provider (MSP) can work with your organization only with your approval. You choose
          which read-only capabilities it gets and for how long, and you can suspend or revoke access at any time.
          Relationship access is read-only. An MSP can start an assessment in your organization only when you approve
          that specific request. MSPs never see your users or billing.
        </p>
        {ownTenant ? (
          <p className="text-xs text-muted">
            Organization ID to share with your MSP: <code data-testid="own-organization-id">{ownTenant}</code>
          </p>
        ) : null}
      </header>

      {notice ? (
        <p role="status" className="text-sm text-success">
          {notice}
        </p>
      ) : null}
      {loadError ? (
        <p role="alert" className="text-sm text-danger">
          {loadError}
        </p>
      ) : null}

      {items === null ? (
        <p aria-live="polite" aria-label="Loading partner relationships" className="text-sm text-muted">
          Loading…
        </p>
      ) : (
        <>
          {section('Requests awaiting your approval', groups.requests, 'No MSP is waiting for your approval.', 'msp-requests')}
          {section('Current access', groups.current, 'No MSP currently has access.', 'msp-current')}
          {section('Ended', groups.ended, 'None.', 'msp-ended')}
        </>
      )}

      {/* MSP-003: renders nothing unless an MSP has sent this organization an assessment request. */}
      <AssessmentGrants party="customer" onSessionExpired={() => setSessionExpired(true)} />

      <ConfirmDialog
        open={pending !== null}
        title={
          pending?.kind === 'approve'
            ? `Approve access for ${pending.rel.counterparty_display_name || 'this MSP'}?`
            : pending
              ? ACTION_COPY[pending.kind].title
              : ''
        }
        description={
          pending?.kind === 'approve'
            ? `You can approve fewer capabilities than requested, never more. Access ends automatically after the period you choose (at most ${MAX_RELATIONSHIP_DAYS} days).`
            : pending
              ? ACTION_COPY[pending.kind].body
              : ''
        }
        confirmLabel={pending?.kind === 'approve' ? 'Approve access' : pending ? ACTION_COPY[pending.kind].confirm : ''}
        destructive={pending?.kind !== 'approve' && pending ? ACTION_COPY[pending.kind].destructive : false}
        busy={busy}
        onCancel={() => setPending(null)}
        onConfirm={() => void confirm()}
      >
        {pending?.kind === 'approve' ? (
          <div className="space-y-4">
            <CapabilityPicker
              legend="Capabilities to approve"
              offered={pending.rel.requested_capabilities}
              selected={selected}
              onChange={setSelected}
              disabled={busy}
            />
            <div className="space-y-1">
              <label htmlFor="approval-days" className="text-sm font-medium">
                Access period (days)
              </label>
              <input
                id="approval-days"
                type="number"
                min={1}
                max={MAX_RELATIONSHIP_DAYS}
                value={days}
                onChange={(e) => setDays(Number(e.target.value))}
                disabled={busy}
                aria-describedby="approval-days-help"
                className="h-9 w-32 rounded border border-border bg-surface-2 px-2 text-sm"
              />
              <p id="approval-days-help" className="text-xs text-muted">
                Between 1 and {MAX_RELATIONSHIP_DAYS} days. Access starts now.
              </p>
            </div>
          </div>
        ) : null}
        {actionError ? (
          <p role="alert" className="mt-3 text-sm text-danger">
            {actionError}
          </p>
        ) : null}
      </ConfirmDialog>
    </main>
  );
}
