'use client';

import { useState, useCallback } from 'react';
import {
  getProviderGovernance,
  getProviderGovernanceDetail,
  getProviderRoutingPolicy,
  getProviderFailoverState,
  type ProviderGovernanceRecord,
  type ProviderGovernancePage,
  type ProviderGovernanceDetail,
  type ProviderRoutingPolicy,
  type ProviderFailoverState,
  type ProviderGovernanceQuery,
  type ProviderOperationalState,
  type ProviderGovernanceState,
  type BaaStatus,
} from '@/lib/coreApi';
import { toErrorDisplay } from '@/lib/errors';

// ─── State label helpers ──────────────────────────────────────────────────────

function operationalStateLabel(state: ProviderOperationalState): string {
  switch (state) {
    case 'healthy': return 'Healthy';
    case 'degraded': return 'Degraded';
    case 'unavailable': return 'Unavailable';
    case 'blocked': return 'Blocked';
    case 'restricted': return 'Restricted';
    case 'maintenance': return 'Maintenance';
    default: return state;
  }
}

function operationalStateClass(state: ProviderOperationalState): string {
  switch (state) {
    case 'healthy': return 'text-success';
    case 'degraded': return 'text-warning';
    case 'unavailable': return 'text-danger';
    case 'blocked': return 'text-danger font-semibold';
    case 'restricted': return 'text-warning';
    case 'maintenance': return 'text-muted';
    default: return 'text-muted';
  }
}

function governanceStateClass(state: ProviderGovernanceState): string {
  switch (state) {
    case 'approved': return 'text-success';
    case 'restricted': return 'text-warning';
    case 'blocked': return 'text-danger font-semibold';
    case 'pending_review': return 'text-warning';
    default: return 'text-muted';
  }
}

function baaStatusLabel(status: BaaStatus | 'missing' | null | undefined): string {
  if (!status) return 'Unknown';
  switch (status) {
    case 'active': return 'Active';
    case 'expired': return 'Expired';
    case 'missing': return 'Missing';
    case 'revoked': return 'Revoked';
    case 'pending': return 'Pending';
    default: return String(status);
  }
}

function baaStatusClass(status: BaaStatus | 'missing' | null | undefined): string {
  switch (status) {
    case 'active': return 'text-success';
    case 'expired': return 'text-danger';
    case 'missing': return 'text-muted';
    case 'revoked': return 'text-danger font-semibold';
    case 'pending': return 'text-warning';
    default: return 'text-muted';
  }
}

function normalizeError(err: unknown): string {
  const display = toErrorDisplay(err) as Partial<{ message: string }>;
  return display?.message || (err instanceof Error ? err.message : 'An error occurred');
}

// ─── ProviderHealthPanel ──────────────────────────────────────────────────────

export interface ProviderHealthPanelProps {
  providers: ProviderGovernanceRecord[];
  loading: boolean;
  error: string | null;
  onRefresh: () => void;
}

export function ProviderHealthPanel({
  providers,
  loading,
  error,
  onRefresh,
}: ProviderHealthPanelProps) {
  if (loading) {
    return (
      <div aria-label="provider-health-loading" className="text-muted text-sm py-4">
        Loading provider health…
      </div>
    );
  }
  if (error) {
    return (
      <div aria-label="provider-health-error" className="text-danger text-sm py-4">
        {error}
        <button
          onClick={onRefresh}
          aria-label="Retry provider health"
          className="ml-2 text-xs underline text-muted hover:text-foreground"
        >
          Retry
        </button>
      </div>
    );
  }
  if (providers.length === 0) {
    return (
      <div aria-label="provider-health-empty" className="text-muted text-sm py-4">
        No provider governance records found.
      </div>
    );
  }

  return (
    <div aria-label="provider-health-panel" className="space-y-2">
      {providers.map((p) => (
        <div
          key={p.provider_id}
          aria-label={`provider-health-${p.provider_id}`}
          className="rounded border border-border bg-surface-2 px-4 py-3 flex flex-wrap items-center gap-4"
        >
          <span className="font-mono text-sm font-semibold text-foreground w-40 truncate">
            {p.provider_id}
          </span>
          <span
            className={`text-xs ${operationalStateClass(p.operational_state)}`}
            aria-label={`operational-state-${p.provider_id}`}
          >
            {operationalStateLabel(p.operational_state)}
          </span>
          <span className="text-xs text-muted">
            Routing: {p.routing_eligible ? 'Eligible' : 'Ineligible'}
          </span>
          <span className="text-xs text-muted">
            Failover: {p.failover_eligible ? 'Ready' : 'Not configured'}
          </span>
        </div>
      ))}
    </div>
  );
}

// ─── ProviderTrustPanel ───────────────────────────────────────────────────────

export interface ProviderTrustPanelProps {
  providers: ProviderGovernanceRecord[];
}

export function ProviderTrustPanel({ providers }: ProviderTrustPanelProps) {
  if (providers.length === 0) {
    return (
      <div aria-label="provider-trust-empty" className="text-muted text-sm py-4">
        No provider trust records available.
      </div>
    );
  }

  return (
    <div aria-label="provider-trust-panel" className="space-y-2">
      {providers.map((p) => (
        <div
          key={p.provider_id}
          aria-label={`provider-trust-${p.provider_id}`}
          className="rounded border border-border bg-surface-2 px-4 py-3 flex flex-wrap items-center gap-4"
        >
          <span className="font-mono text-sm font-semibold text-foreground w-40 truncate">
            {p.provider_id}
          </span>
          <span
            className={`text-xs ${governanceStateClass(p.governance_state)}`}
            aria-label={`governance-state-${p.provider_id}`}
          >
            {p.governance_state}
          </span>
          <span className="text-xs text-muted" aria-label={`trust-class-${p.provider_id}`}>
            Trust: {p.trust_classification}
          </span>
          {p.restrictions.length > 0 && (
            <span className="text-xs text-warning" aria-label={`restrictions-${p.provider_id}`}>
              {p.restrictions.length} restriction{p.restrictions.length !== 1 ? 's' : ''}
            </span>
          )}
          {p.block_reason && (
            <span className="text-xs text-danger" aria-label={`block-reason-${p.provider_id}`}>
              Blocked: {p.block_reason}
            </span>
          )}
        </div>
      ))}
    </div>
  );
}

// ─── BAACompliancePanel ───────────────────────────────────────────────────────

export interface BAACompliancePanelProps {
  routingPolicy: ProviderRoutingPolicy | null;
  loading: boolean;
  error: string | null;
}

export function BAACompliancePanel({
  routingPolicy,
  loading,
  error,
}: BAACompliancePanelProps) {
  if (loading) {
    return (
      <div aria-label="baa-compliance-loading" className="text-muted text-sm py-4">
        Loading BAA compliance state…
      </div>
    );
  }
  if (error) {
    return (
      <div aria-label="baa-compliance-error" className="text-danger text-sm py-4">
        {error}
      </div>
    );
  }
  if (!routingPolicy) {
    return (
      <div aria-label="baa-compliance-empty" className="text-muted text-sm py-4">
        No routing policy available.
      </div>
    );
  }

  const allProviders = [
    ...routingPolicy.allowed_providers,
    ...routingPolicy.blocked_providers,
    ...routingPolicy.restricted_providers,
    ...routingPolicy.failover_providers,
  ];

  return (
    <div aria-label="baa-compliance-panel" className="space-y-2">
      {allProviders.map((p) => (
        <div
          key={p.provider_id}
          aria-label={`baa-compliance-${p.provider_id}`}
          className="rounded border border-border bg-surface-2 px-4 py-3 flex flex-wrap items-center gap-4"
        >
          <span className="font-mono text-sm font-semibold text-foreground w-40 truncate">
            {p.provider_id}
          </span>
          <span
            className={`text-xs ${baaStatusClass(p.baa_status)}`}
            aria-label={`baa-status-${p.provider_id}`}
          >
            BAA: {baaStatusLabel(p.baa_status)}
          </span>
          <span className="text-xs text-muted">
            Trust: {p.trust_classification}
          </span>
        </div>
      ))}
    </div>
  );
}

// ─── TenantRoutingPanel ───────────────────────────────────────────────────────

export interface TenantRoutingPanelProps {
  routingPolicy: ProviderRoutingPolicy | null;
  loading: boolean;
  error: string | null;
}

export function TenantRoutingPanel({
  routingPolicy,
  loading,
  error,
}: TenantRoutingPanelProps) {
  if (loading) {
    return (
      <div aria-label="tenant-routing-loading" className="text-muted text-sm py-4">
        Loading routing policy…
      </div>
    );
  }
  if (error) {
    return (
      <div aria-label="tenant-routing-error" className="text-danger text-sm py-4">
        {error}
      </div>
    );
  }
  if (!routingPolicy) {
    return (
      <div aria-label="tenant-routing-empty" className="text-muted text-sm py-4">
        No routing policy available.
      </div>
    );
  }

  return (
    <div aria-label="tenant-routing-panel" className="space-y-4">
      {routingPolicy.allowed_providers.length > 0 && (
        <section aria-label="allowed-providers-section">
          <h4 className="text-xs font-semibold text-muted uppercase mb-2">Allowed</h4>
          <div className="space-y-1">
            {routingPolicy.allowed_providers.map((p) => (
              <div key={p.provider_id} aria-label={`allowed-${p.provider_id}`}
                className="font-mono text-sm text-success">
                {p.provider_id}
              </div>
            ))}
          </div>
        </section>
      )}
      {routingPolicy.blocked_providers.length > 0 && (
        <section aria-label="blocked-providers-section">
          <h4 className="text-xs font-semibold text-muted uppercase mb-2">Blocked</h4>
          <div className="space-y-1">
            {routingPolicy.blocked_providers.map((p) => (
              <div key={p.provider_id} aria-label={`blocked-${p.provider_id}`}
                className="font-mono text-sm text-danger">
                {p.provider_id}
              </div>
            ))}
          </div>
        </section>
      )}
      {routingPolicy.restricted_providers.length > 0 && (
        <section aria-label="restricted-providers-section">
          <h4 className="text-xs font-semibold text-muted uppercase mb-2">Restricted</h4>
          <div className="space-y-1">
            {routingPolicy.restricted_providers.map((p) => (
              <div key={p.provider_id} aria-label={`restricted-${p.provider_id}`}
                className="font-mono text-sm text-warning">
                {p.provider_id}
              </div>
            ))}
          </div>
        </section>
      )}
      {routingPolicy.failover_providers.length > 0 && (
        <section aria-label="failover-providers-section">
          <h4 className="text-xs font-semibold text-muted uppercase mb-2">Failover</h4>
          <div className="space-y-1">
            {routingPolicy.failover_providers.map((p) => (
              <div key={p.provider_id} aria-label={`failover-${p.provider_id}`}
                className="font-mono text-sm text-muted">
                {p.provider_id}
              </div>
            ))}
          </div>
        </section>
      )}
      <p className="text-xs text-muted mt-2">{routingPolicy.routing_policy_note}</p>
    </div>
  );
}

// ─── FailoverVisibilityPanel ──────────────────────────────────────────────────

export interface FailoverVisibilityPanelProps {
  failoverState: ProviderFailoverState | null;
  loading: boolean;
  error: string | null;
  onRefresh: () => void;
}

export function FailoverVisibilityPanel({
  failoverState,
  loading,
  error,
  onRefresh,
}: FailoverVisibilityPanelProps) {
  if (loading) {
    return (
      <div aria-label="failover-loading" className="text-muted text-sm py-4">
        Loading failover state…
      </div>
    );
  }
  if (error) {
    return (
      <div aria-label="failover-error" className="text-danger text-sm py-4">
        {error}
        <button
          onClick={onRefresh}
          aria-label="Retry failover state"
          className="ml-2 text-xs underline text-muted hover:text-foreground"
        >
          Retry
        </button>
      </div>
    );
  }
  if (!failoverState) {
    return (
      <div aria-label="failover-empty" className="text-muted text-sm py-4">
        No failover data available.
      </div>
    );
  }

  return (
    <div aria-label="failover-visibility-panel" className="space-y-4">
      <div className="rounded border border-border bg-surface-2 px-4 py-2 text-xs text-muted">
        {failoverState.failover_note}
      </div>
      {!failoverState.telemetry_available && (
        <div aria-label="no-telemetry-notice" className="text-xs text-muted">
          Live telemetry not available. Showing governance-derived state only.
        </div>
      )}
      {failoverState.degraded_providers.length === 0 &&
        failoverState.failover_ready_providers.length === 0 && (
          <div className="text-muted text-sm">No degraded or failover-ready providers.</div>
        )}
      {failoverState.degraded_providers.length > 0 && (
        <section aria-label="degraded-providers-section">
          <h4 className="text-xs font-semibold text-muted uppercase mb-2">Degraded / Unavailable</h4>
          <div className="space-y-1">
            {failoverState.degraded_providers.map((p) => (
              <div key={p.provider_id} aria-label={`degraded-${p.provider_id}`}
                className="flex items-center gap-3 font-mono text-sm">
                <span className="text-warning">{p.provider_id}</span>
                <span className="text-xs text-muted">{p.operational_state}</span>
              </div>
            ))}
          </div>
        </section>
      )}
      {failoverState.failover_ready_providers.length > 0 && (
        <section aria-label="failover-ready-section">
          <h4 className="text-xs font-semibold text-muted uppercase mb-2">Failover Ready</h4>
          <div className="space-y-1">
            {failoverState.failover_ready_providers.map((p) => (
              <div key={p.provider_id} aria-label={`failover-ready-${p.provider_id}`}
                className="flex items-center gap-3 font-mono text-sm">
                <span className="text-success">{p.provider_id}</span>
                <span className="text-xs text-muted">{p.operational_state}</span>
              </div>
            ))}
          </div>
        </section>
      )}
    </div>
  );
}

// ─── ProviderGovernanceConsole ────────────────────────────────────────────────

export interface ProviderGovernanceConsoleProps {
  defaultTab?: 'health' | 'trust' | 'baa' | 'routing' | 'failover';
}

type Tab = 'health' | 'trust' | 'baa' | 'routing' | 'failover';

export function ProviderGovernanceConsole({
  defaultTab = 'health',
}: ProviderGovernanceConsoleProps) {
  const [tab, setTab] = useState<Tab>(defaultTab);

  const [govPage, setGovPage] = useState<ProviderGovernancePage | null>(null);
  const [govLoading, setGovLoading] = useState(false);
  const [govError, setGovError] = useState<string | null>(null);

  const [routingPolicy, setRoutingPolicy] = useState<ProviderRoutingPolicy | null>(null);
  const [routingLoading, setRoutingLoading] = useState(false);
  const [routingError, setRoutingError] = useState<string | null>(null);

  const [failoverState, setFailoverState] = useState<ProviderFailoverState | null>(null);
  const [failoverLoading, setFailoverLoading] = useState(false);
  const [failoverError, setFailoverError] = useState<string | null>(null);

  const loadGovernance = useCallback(async () => {
    setGovLoading(true);
    setGovError(null);
    try {
      const page = await getProviderGovernance();
      setGovPage(page);
    } catch (err) {
      setGovError(normalizeError(err));
    } finally {
      setGovLoading(false);
    }
  }, []);

  const loadRouting = useCallback(async () => {
    setRoutingLoading(true);
    setRoutingError(null);
    try {
      const policy = await getProviderRoutingPolicy();
      setRoutingPolicy(policy);
    } catch (err) {
      setRoutingError(normalizeError(err));
    } finally {
      setRoutingLoading(false);
    }
  }, []);

  const loadFailover = useCallback(async () => {
    setFailoverLoading(true);
    setFailoverError(null);
    try {
      const state = await getProviderFailoverState();
      setFailoverState(state);
    } catch (err) {
      setFailoverError(normalizeError(err));
    } finally {
      setFailoverLoading(false);
    }
  }, []);

  function handleTabChange(newTab: Tab) {
    setTab(newTab);
    if ((newTab === 'health' || newTab === 'trust') && !govPage && !govLoading) {
      loadGovernance();
    }
    if ((newTab === 'baa' || newTab === 'routing') && !routingPolicy && !routingLoading) {
      loadRouting();
    }
    if (newTab === 'failover' && !failoverState && !failoverLoading) {
      loadFailover();
    }
  }

  const tabs: { id: Tab; label: string }[] = [
    { id: 'health', label: 'Provider Health' },
    { id: 'trust', label: 'Trust Posture' },
    { id: 'baa', label: 'BAA Compliance' },
    { id: 'routing', label: 'Routing Policy' },
    { id: 'failover', label: 'Failover' },
  ];

  const providers = govPage?.providers ?? [];

  return (
    <div aria-label="provider-governance-console" className="space-y-4">
      <nav aria-label="provider-governance-tabs" className="flex gap-1 flex-wrap">
        {tabs.map((t) => (
          <button
            key={t.id}
            onClick={() => handleTabChange(t.id)}
            aria-label={`tab-${t.id}`}
            aria-pressed={tab === t.id}
            className={`rounded px-3 py-1.5 text-xs font-medium border transition-colors ${
              tab === t.id
                ? 'border-primary bg-primary/10 text-primary'
                : 'border-border text-muted hover:text-foreground'
            }`}
          >
            {t.label}
          </button>
        ))}
      </nav>

      <div className="mt-4">
        {tab === 'health' && (
          <section aria-label="health-tab-content">
            <div className="flex items-center justify-between mb-3">
              <h3 className="text-sm font-semibold text-foreground">Provider Health</h3>
              <button
                onClick={loadGovernance}
                disabled={govLoading}
                aria-label="Refresh provider health"
                className="text-xs text-muted hover:text-foreground disabled:opacity-40"
              >
                {govLoading ? 'Loading…' : 'Refresh'}
              </button>
            </div>
            <ProviderHealthPanel
              providers={providers}
              loading={govLoading && !govPage}
              error={govError}
              onRefresh={loadGovernance}
            />
          </section>
        )}

        {tab === 'trust' && (
          <section aria-label="trust-tab-content">
            <h3 className="text-sm font-semibold text-foreground mb-3">Trust Posture</h3>
            {govLoading && !govPage ? (
              <div className="text-muted text-sm">Loading…</div>
            ) : govError ? (
              <div className="text-danger text-sm">{govError}</div>
            ) : (
              <ProviderTrustPanel providers={providers} />
            )}
          </section>
        )}

        {tab === 'baa' && (
          <section aria-label="baa-tab-content">
            <h3 className="text-sm font-semibold text-foreground mb-3">BAA Compliance</h3>
            <BAACompliancePanel
              routingPolicy={routingPolicy}
              loading={routingLoading && !routingPolicy}
              error={routingError}
            />
          </section>
        )}

        {tab === 'routing' && (
          <section aria-label="routing-tab-content">
            <h3 className="text-sm font-semibold text-foreground mb-3">Routing Policy</h3>
            <TenantRoutingPanel
              routingPolicy={routingPolicy}
              loading={routingLoading && !routingPolicy}
              error={routingError}
            />
          </section>
        )}

        {tab === 'failover' && (
          <section aria-label="failover-tab-content">
            <h3 className="text-sm font-semibold text-foreground mb-3">Failover Visibility</h3>
            <FailoverVisibilityPanel
              failoverState={failoverState}
              loading={failoverLoading && !failoverState}
              error={failoverError}
              onRefresh={loadFailover}
            />
          </section>
        )}
      </div>
    </div>
  );
}
