'use client';

/**
 * MSP-003 — customer-approved assessment requests, for either party.
 *
 * MSP view (party="msp", for one selected customer): request an assessment,
 * withdraw a pending request, start an approved one, follow its progress.
 * Customer view (party="customer"): review, approve, decline, revoke. Renders
 * nothing for an organization with no requests, so direct customers see no
 * MSP controls.
 *
 * Every button only asks Core; Core decides (api/msp_orchestration.py). The
 * list is reloaded after every action so stale state never authorizes
 * anything. Starting an assessment is not billable and skips no gate.
 */

import { useCallback, useEffect, useState } from 'react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';
import { ConfirmDialog } from '@/components/msp/ConfirmDialog';
import {
  decideAssessmentGrant,
  initiateAssessment,
  listAllAssessmentGrants,
  requestAssessmentGrant,
  type AssessmentGrant,
  type GrantDecision,
} from '@/lib/mspApi';
import {
  ASSESSMENT_TYPES,
  DEFAULT_GRANT_DAYS,
  MAX_GRANT_DAYS,
  assessmentTypeLabel,
  blockerLabel,
  buildGrantRequestBody,
  grantActions,
  grantStatusView,
  newRequestKey,
  nextActionLabel,
  progressLabel,
  safeOrchestrationError,
} from '@/lib/mspOrchestration';

interface Props {
  party: 'msp' | 'customer';
  /** MSP view only: the selected customer. Display filter, never authority. */
  customerTenantId?: string;
  onSessionExpired?: () => void;
}

const CONFIRM: Record<GrantDecision, { title: string; description: string; label: string; destructive: boolean }> = {
  approve: {
    title: 'Approve this assessment request?',
    description:
      'The MSP may start exactly one assessment of this type with this assessor, until the date shown. The assessment stays in your organization; your own reviewers still control QA approval and delivery. You can revoke this at any time.',
    label: 'Approve',
    destructive: false,
  },
  reject: {
    title: 'Decline this assessment request?',
    description: 'The MSP cannot start this assessment. They can send a new request.',
    label: 'Decline',
    destructive: true,
  },
  revoke: {
    title: 'Revoke this assessment authority?',
    description:
      'The MSP can no longer start this assessment or see its progress. An assessment already started is not cancelled; it remains yours.',
    label: 'Revoke',
    destructive: true,
  },
  withdraw: {
    title: 'Withdraw this request?',
    description: 'The customer will no longer see it as pending. You can send a new request later.',
    label: 'Withdraw',
    destructive: true,
  },
};

function fmtDate(iso: string | null | undefined): string {
  return iso ? new Date(iso).toLocaleDateString() : '—';
}

export function AssessmentGrants({ party, customerTenantId, onSessionExpired }: Props) {
  const [grants, setGrants] = useState<AssessmentGrant[] | null>(null);
  const [error, setError] = useState('');
  const [pending, setPending] = useState<{ grant: AssessmentGrant; action: GrantDecision } | null>(null);
  const [busy, setBusy] = useState(false);
  const [actionError, setActionError] = useState('');
  const [message, setMessage] = useState<{ ok: boolean; text: string } | null>(null);
  const [assessmentType, setAssessmentType] = useState('ai_governance');
  const [assessorId, setAssessorId] = useState('');
  const [days, setDays] = useState(DEFAULT_GRANT_DAYS);
  const [requestKey, setRequestKey] = useState(() => newRequestKey('grant'));

  const load = useCallback(async () => {
    const res = await listAllAssessmentGrants(party === 'msp' ? customerTenantId : undefined);
    if (!res.ok) {
      if (res.status === 401) onSessionExpired?.();
      setError(safeOrchestrationError(res));
      setGrants([]);
      return;
    }
    setError('');
    setGrants(res.data.items.filter((g) => g.party === party));
  }, [party, customerTenantId, onSessionExpired]);

  useEffect(() => {
    void load();
  }, [load]);

  const fail = (res: { ok: false; status?: number; code?: string }) => {
    if (res.status === 401) onSessionExpired?.();
    return safeOrchestrationError(res);
  };

  const confirm = async () => {
    if (!pending || busy) return;
    setBusy(true);
    setActionError('');
    try {
      const res = await decideAssessmentGrant(pending.grant.grant_id, pending.action, pending.grant.version);
      if (!res.ok) {
        setActionError(fail(res));
        await load();
        return;
      }
      setPending(null);
      await load();
    } finally {
      setBusy(false);
    }
  };

  const start = async (grant: AssessmentGrant) => {
    if (busy) return;
    setBusy(true);
    setMessage(null);
    try {
      const res = await initiateAssessment(grant.grant_id);
      if (!res.ok) {
        setMessage({ ok: false, text: fail(res) });
      } else {
        setMessage({
          ok: true,
          text: res.data.created
            ? 'Assessment started in the customer’s organization. It is not billed until it is delivered.'
            : 'This assessment was already started.',
        });
      }
      await load();
    } finally {
      setBusy(false);
    }
  };

  const submitRequest = async () => {
    if (busy || !customerTenantId) return;
    setMessage(null);
    const built = buildGrantRequestBody({ customerTenantId, assessmentType, assessorId, days, requestKey });
    if (!built.ok) {
      setMessage({ ok: false, text: built.error });
      return;
    }
    setBusy(true);
    try {
      const res = await requestAssessmentGrant(built.body);
      if (!res.ok) {
        setMessage({ ok: false, text: fail(res) });
        return;
      }
      setMessage({
        ok: true,
        text: res.data.created
          ? 'Request sent. The customer’s administrator must approve it before you can start the assessment.'
          : 'This request was already sent.',
      });
      setRequestKey(newRequestKey('grant'));
      setAssessorId('');
      await load();
    } finally {
      setBusy(false);
    }
  };

  if (party === 'customer' && grants !== null && grants.length === 0 && !error) return null;

  return (
    <section aria-labelledby={`grants-${party}-h`} className="space-y-3" data-testid={`msp-grants-${party}`}>
      <h2 id={`grants-${party}-h`} className="text-lg font-semibold">
        {party === 'msp' ? 'Assessments for this customer' : 'Assessment requests from your MSP'}
      </h2>
      {party === 'customer' ? (
        <p className="text-sm text-muted">
          An MSP can start an assessment in your organization only with your approval of each request. Approval covers
          one assessment, is time-limited, and never lets the MSP approve QA, deliver reports, or see more than you
          delegated.
        </p>
      ) : null}
      {error ? (
        <p role="alert" className="text-sm text-danger">
          {error}
        </p>
      ) : null}
      {grants === null ? (
        <p aria-live="polite" className="text-sm text-muted">
          Loading…
        </p>
      ) : grants.length === 0 ? (
        <p className="text-sm text-muted">No assessment requests yet.</p>
      ) : (
        grants.map((g) => {
          const status = grantStatusView(g);
          const actions = grantActions(g);
          return (
            <Card key={g.grant_id} data-testid="msp-grant">
              <CardContent className="space-y-2 p-4 text-sm">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span className="font-medium">
                    {assessmentTypeLabel(g.scope.assessment_type)} · assessor {g.scope.assessor_id}
                  </span>
                  <Badge variant={status.tone}>{status.label}</Badge>
                </div>
                <p className="text-xs text-muted">
                  {party === 'customer' ? `Requested by MSP ${g.msp_tenant_id}` : `Customer ${g.customer_tenant_id}`} ·
                  valid until {fmtDate(g.expires_at)}
                </p>
                {g.engagement_id ? (
                  <p>
                    <span className="font-medium">Progress:</span> {progressLabel(g.progress)}
                  </p>
                ) : null}
                {party === 'msp' && g.blockers.length > 0 && g.status === 'approved' ? (
                  <ul className="list-disc pl-5 text-xs text-muted" aria-label="Why this cannot start">
                    {g.blockers.map((b) => (
                      <li key={b}>{blockerLabel(b)}</li>
                    ))}
                  </ul>
                ) : null}
                {g.next_actions.length > 0 ? (
                  <p className="text-xs">
                    <span className="font-medium">Next:</span> {g.next_actions.map(nextActionLabel).join('; ')}
                  </p>
                ) : null}
                {actions.length > 0 ? (
                  <div className="flex gap-2">
                    {actions.map((a) =>
                      a === 'initiate' ? (
                        <Button key={a} size="sm" onClick={() => void start(g)} loading={busy} disabled={busy}>
                          Start assessment
                        </Button>
                      ) : (
                        <Button
                          key={a}
                          size="sm"
                          variant={a === 'approve' ? 'default' : 'outline'}
                          disabled={busy}
                          onClick={() => {
                            setActionError('');
                            setPending({ grant: g, action: a });
                          }}
                        >
                          {CONFIRM[a].label}
                        </Button>
                      ),
                    )}
                  </div>
                ) : null}
              </CardContent>
            </Card>
          );
        })
      )}

      {party === 'msp' && customerTenantId ? (
        <form
          className="space-y-3 border-t border-border pt-3"
          data-testid="msp-grant-request"
          onSubmit={(e) => {
            e.preventDefault();
            void submitRequest();
          }}
        >
          <h3 className="text-sm font-semibold">Request an assessment</h3>
          <p className="text-xs text-muted">
            The customer’s administrator approves each assessment. Approval lasts at most {MAX_GRANT_DAYS} days and
            covers one assessment.
          </p>
          <div className="flex flex-wrap gap-3">
            <label className="space-y-1 text-sm">
              <span className="block font-medium">Assessment type</span>
              <select
                value={assessmentType}
                onChange={(e) => setAssessmentType(e.target.value)}
                disabled={busy}
                className="h-9 rounded border border-border bg-surface-2 px-2"
              >
                {ASSESSMENT_TYPES.map((t) => (
                  <option key={t.id} value={t.id}>
                    {t.label}
                  </option>
                ))}
              </select>
            </label>
            <label className="space-y-1 text-sm">
              <span className="block font-medium">Assessor</span>
              <input
                value={assessorId}
                onChange={(e) => setAssessorId(e.target.value)}
                disabled={busy}
                autoComplete="off"
                className="h-9 w-56 rounded border border-border bg-surface-2 px-2"
              />
            </label>
            <label className="space-y-1 text-sm">
              <span className="block font-medium">Days</span>
              <input
                type="number"
                min={1}
                max={MAX_GRANT_DAYS}
                value={days}
                onChange={(e) => setDays(Number(e.target.value))}
                disabled={busy}
                className="h-9 w-20 rounded border border-border bg-surface-2 px-2"
              />
            </label>
          </div>
          <Button type="submit" size="sm" loading={busy} aria-busy={busy}>
            Send request
          </Button>
        </form>
      ) : null}
      {message ? (
        <p role={message.ok ? 'status' : 'alert'} className={message.ok ? 'text-sm text-success' : 'text-sm text-danger'}>
          {message.text}
        </p>
      ) : null}

      <ConfirmDialog
        open={pending !== null}
        title={pending ? CONFIRM[pending.action].title : ''}
        description={pending ? CONFIRM[pending.action].description : ''}
        confirmLabel={pending ? CONFIRM[pending.action].label : ''}
        destructive={pending ? CONFIRM[pending.action].destructive : false}
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
