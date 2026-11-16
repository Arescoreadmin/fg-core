'use client';

/**
 * MSP-003 — refer a new organization to FrostGate (MSP view).
 *
 * A referral creates no account, user, invitation or access. FrostGate
 * reviews it and provisions the organization through its own canonical
 * process; the stage shown afterwards is derived by Core from that
 * organization's real lifecycle and the MSP relationship. The MSP then
 * requests access through the normal relationship flow, which the customer
 * approves.
 */

import { useCallback, useEffect, useState } from 'react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';
import { CapabilityPicker } from '@/components/msp/CapabilityPicker';
import {
  cancelOnboarding,
  listOnboardingRequests,
  requestOnboarding,
  type OnboardingRequest,
} from '@/lib/mspApi';
import {
  buildOnboardingBody,
  newRequestKey,
  nextActionLabel,
  onboardingStageView,
  safeOrchestrationError,
} from '@/lib/mspOrchestration';

function fmtDate(iso: string | null | undefined): string {
  return iso ? new Date(iso).toLocaleDateString() : '—';
}

export function OnboardingRequests({ onSessionExpired }: { onSessionExpired?: () => void }) {
  const [items, setItems] = useState<OnboardingRequest[] | null>(null);
  const [error, setError] = useState('');
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [caps, setCaps] = useState<string[]>(['assessment.read', 'finding.read']);
  const [requestKey, setRequestKey] = useState(() => newRequestKey('onb'));
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<{ ok: boolean; text: string } | null>(null);

  const load = useCallback(async () => {
    const res = await listOnboardingRequests();
    if (!res.ok) {
      if (res.status === 401) onSessionExpired?.();
      setError(safeOrchestrationError(res));
      setItems([]);
      return;
    }
    setError('');
    setItems(res.data.items);
  }, [onSessionExpired]);

  useEffect(() => {
    void load();
  }, [load]);

  const submit = async () => {
    if (busy) return;
    setMessage(null);
    const built = buildOnboardingBody({ organizationName: name, contactEmail: email, selected: caps, requestKey });
    if (!built.ok) {
      setMessage({ ok: false, text: built.error });
      return;
    }
    setBusy(true);
    try {
      const res = await requestOnboarding(built.body);
      if (!res.ok) {
        if (res.status === 401) onSessionExpired?.();
        setMessage({ ok: false, text: safeOrchestrationError(res) });
        return;
      }
      setMessage({
        ok: true,
        text: res.data.created
          ? 'Referral sent to FrostGate for review. No account or access is created until FrostGate and the customer act.'
          : 'This referral was already sent.',
      });
      setName('');
      setEmail('');
      setRequestKey(newRequestKey('onb'));
      await load();
    } finally {
      setBusy(false);
    }
  };

  const cancel = async (item: OnboardingRequest) => {
    if (busy) return;
    setBusy(true);
    try {
      const res = await cancelOnboarding(item.onboarding_request_id, item.version);
      if (!res.ok) setMessage({ ok: false, text: safeOrchestrationError(res) });
      await load();
    } finally {
      setBusy(false);
    }
  };

  return (
    <section aria-labelledby="msp-onboarding-h" className="space-y-3" data-testid="msp-onboarding">
      <h2 id="msp-onboarding-h" className="text-lg font-semibold">
        Onboard a new customer
      </h2>
      <p className="text-sm text-muted">
        For an organization that is not on FrostGate yet. FrostGate reviews the referral and sets up the account; the
        customer’s own administrator then accepts and approves your access. For an existing customer, use “Request
        access to a customer” instead.
      </p>
      {error ? (
        <p role="alert" className="text-sm text-danger">
          {error}
        </p>
      ) : null}
      {items && items.length > 0 ? (
        items.map((item) => {
          const stage = onboardingStageView(item.stage);
          return (
            <Card key={item.onboarding_request_id} data-testid="msp-onboarding-item">
              <CardContent className="space-y-1 p-4 text-sm">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span className="font-medium">{item.organization_name}</span>
                  <Badge variant={stage.tone}>{stage.label}</Badge>
                </div>
                <p className="text-xs text-muted">
                  Sent {fmtDate(item.requested_at)}
                  {item.customer_tenant_id ? ` · organization ID ${item.customer_tenant_id}` : ''}
                </p>
                {item.next_actions.length > 0 ? (
                  <p className="text-xs">
                    <span className="font-medium">Next:</span> {item.next_actions.map(nextActionLabel).join('; ')}
                  </p>
                ) : null}
                {item.stage === 'requested' ? (
                  <Button size="sm" variant="outline" disabled={busy} onClick={() => void cancel(item)}>
                    Cancel referral
                  </Button>
                ) : null}
              </CardContent>
            </Card>
          );
        })
      ) : items !== null ? (
        <p className="text-sm text-muted">No referrals yet.</p>
      ) : null}
      <form
        className="space-y-3"
        onSubmit={(e) => {
          e.preventDefault();
          void submit();
        }}
      >
        <div className="flex flex-wrap gap-3">
          <label className="space-y-1 text-sm">
            <span className="block font-medium">Organization name</span>
            <input
              value={name}
              onChange={(e) => setName(e.target.value)}
              disabled={busy}
              autoComplete="off"
              className="h-9 w-64 rounded border border-border bg-surface-2 px-2"
            />
          </label>
          <label className="space-y-1 text-sm">
            <span className="block font-medium">Their administrator’s email</span>
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              disabled={busy}
              autoComplete="off"
              className="h-9 w-64 rounded border border-border bg-surface-2 px-2"
            />
          </label>
        </div>
        <CapabilityPicker legend="Access you will request once they join" selected={caps} onChange={setCaps} disabled={busy} />
        <Button type="submit" size="sm" loading={busy} aria-busy={busy}>
          Send referral
        </Button>
        {message ? (
          <p role={message.ok ? 'status' : 'alert'} className={message.ok ? 'text-sm text-success' : 'text-sm text-danger'}>
            {message.text}
          </p>
        ) : null}
      </form>
    </section>
  );
}
