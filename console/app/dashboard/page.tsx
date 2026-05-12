'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';
import {
  Activity,
  AlertCircle,
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  Clock,
  CreditCard,
  FileCheck,
  FileText,
  GitBranch,
  HelpCircle,
  Info,
  Key,
  Layers,
  Loader2,
  Network,
  Plus,
  Shield,
  TrendingUp,
  Users,
} from 'lucide-react';
import { TopBar } from '@/components/layout/TopBar';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { DomainScores } from '@/components/dashboard/DomainScores';
import { RequestsChart } from '@/components/dashboard/RequestsChart';
import {
  getBillingReadiness,
  getCommandCenterSnapshot,
  getRecentFeedEvents,
  type BillingReadiness,
  type ControlTowerSnapshotV1,
  type FeedItem,
  type FeedLiveResponse,
  type SafeResult,
} from '@/lib/coreApi';
import { mapToSeverity, type Severity } from '@/lib/severity';

// ─── Types ────────────────────────────────────────────────────────────────────

interface DashboardStats {
  total_requests: number;
  blocked_requests: number;
  active_tenants: number;
  active_keys: number;
  block_rate?: number;
}

interface HealthData {
  service: string;
  version: string;
  status: string;
  billing?: BillingReadiness;
  dependencies?: Record<string, string>;
}

interface ChartPoint {
  time: string;
  allowed: number;
  blocked: number;
}

// ─── Severity display ─────────────────────────────────────────────────────────

const SEVERITY_CONFIG: Record<
  Severity,
  { label: string; className: string; Icon: React.ComponentType<{ className?: string }> }
> = {
  ok:       { label: 'Healthy',  className: 'text-success', Icon: CheckCircle2 },
  info:     { label: 'Info',     className: 'text-primary', Icon: Info },
  warning:  { label: 'Warning',  className: 'text-warning', Icon: AlertTriangle },
  critical: { label: 'Critical', className: 'text-danger',  Icon: AlertCircle },
  unknown:  { label: 'Unknown',  className: 'text-muted',   Icon: HelpCircle },
};

function SeverityIndicator({ severity, label }: { severity: Severity; label?: string }) {
  const { label: defaultLabel, className, Icon } = SEVERITY_CONFIG[severity];
  const displayLabel = label ?? defaultLabel;
  return (
    <span className={`inline-flex items-center gap-1.5 text-sm font-medium ${className}`}>
      <Icon className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
      {displayLabel}
    </span>
  );
}

// ─── Widget shell ─────────────────────────────────────────────────────────────

function WidgetShell({
  title,
  icon: Icon,
  children,
  ariaLabel,
}: {
  title: string;
  icon: React.ComponentType<{ className?: string }>;
  children: React.ReactNode;
  ariaLabel?: string;
}) {
  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="flex items-center gap-2 text-sm font-medium">
          <Icon className="h-4 w-4 shrink-0 text-primary" aria-hidden="true" />
          {title}
        </CardTitle>
      </CardHeader>
      <CardContent aria-label={ariaLabel}>{children}</CardContent>
    </Card>
  );
}

// ─── Command Center widgets ───────────────────────────────────────────────────

function SystemHealthWidget({
  health,
  loading,
  coreError,
}: {
  health: HealthData | null;
  loading: boolean;
  coreError: boolean;
}) {
  const severity: Severity = loading
    ? 'unknown'
    : coreError
      ? 'critical'
      : mapToSeverity(health?.status ?? 'ok');

  return (
    <WidgetShell title="System Health" icon={Activity} ariaLabel="system-health-widget">
      {loading ? (
        <div className="flex items-center gap-2 text-sm text-muted" aria-label="system-health-loading">
          <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />
          Checking system health…
        </div>
      ) : coreError ? (
        <div aria-label="system-health-critical">
          <SeverityIndicator severity="critical" label="Core unreachable" />
          <p className="mt-1 text-xs text-muted">Admin-gateway is not reachable.</p>
        </div>
      ) : (
        <div aria-label="system-health-ok">
          <SeverityIndicator severity={severity} />
          {health?.service && (
            <p className="mt-1.5 text-xs text-muted">
              {health.service} v{health.version}
            </p>
          )}
          {health?.dependencies && Object.keys(health.dependencies).length > 0 && (
            <ul className="mt-2 space-y-1" aria-label="dependency-statuses">
              {Object.entries(health.dependencies)
                .slice(0, 4)
                .map(([dep, st]) => (
                  <li key={dep} className="flex items-center justify-between text-xs">
                    <span className="max-w-[120px] truncate font-mono text-muted">{dep}</span>
                    <SeverityIndicator severity={mapToSeverity(st)} label={st} />
                  </li>
                ))}
            </ul>
          )}
        </div>
      )}
    </WidgetShell>
  );
}

const RETRIEVAL_PLANE_KEYS = ['retrieval', 'rag', 'hybrid_retrieval', 'retrieval_plane', 'embedding'];

function RetrievalHealthWidget({
  ctResult,
  ctLoading,
}: {
  ctResult: SafeResult<ControlTowerSnapshotV1> | null;
  ctLoading: boolean;
}) {
  if (ctLoading) {
    return (
      <WidgetShell title="Retrieval Health" icon={Layers}>
        <div className="flex items-center gap-2 text-sm text-muted" aria-label="retrieval-health-loading">
          <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />
          Loading…
        </div>
      </WidgetShell>
    );
  }

  if (!ctResult || !ctResult.ok) {
    return (
      <WidgetShell title="Retrieval Health" icon={Layers}>
        <div aria-label="retrieval-health-unavailable">
          <SeverityIndicator severity="unknown" label="Status unavailable" />
          <p className="mt-1 text-xs text-muted">Control tower snapshot unavailable.</p>
        </div>
      </WidgetShell>
    );
  }

  const planes = ctResult.data.planes ?? {};
  const retrievalEntries = Object.entries(planes).filter(([k]) =>
    RETRIEVAL_PLANE_KEYS.some((rk) => k.toLowerCase().includes(rk)),
  );

  if (retrievalEntries.length === 0) {
    return (
      <WidgetShell title="Retrieval Health" icon={Layers}>
        <div aria-label="retrieval-health-no-plane">
          <SeverityIndicator severity="unknown" label="No retrieval plane registered" />
          <p className="mt-1 text-xs text-muted">No retrieval plane found in snapshot.</p>
        </div>
      </WidgetShell>
    );
  }

  const severityOrder: Record<Severity, number> = {
    ok: 0, info: 1, unknown: 2, warning: 3, critical: 4,
  };
  const worst = retrievalEntries.reduce<Severity>((acc, [, st]) => {
    const sev = mapToSeverity(st);
    return severityOrder[sev] > severityOrder[acc] ? sev : acc;
  }, 'ok');

  return (
    <WidgetShell title="Retrieval Health" icon={Layers} ariaLabel="retrieval-health-widget">
      <SeverityIndicator severity={worst} />
      <ul className="mt-2 space-y-1">
        {retrievalEntries.map(([k, st]) => (
          <li key={k} className="flex items-center justify-between text-xs">
            <span className="max-w-[120px] truncate font-mono text-muted">{k}</span>
            <SeverityIndicator severity={mapToSeverity(st)} label={st} />
          </li>
        ))}
      </ul>
    </WidgetShell>
  );
}

function AuditStatusWidget({
  ctResult,
  ctLoading,
}: {
  ctResult: SafeResult<ControlTowerSnapshotV1> | null;
  ctLoading: boolean;
}) {
  if (ctLoading) {
    return (
      <WidgetShell title="Audit Status" icon={FileCheck}>
        <div className="flex items-center gap-2 text-sm text-muted" aria-label="audit-status-loading">
          <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />
          Loading…
        </div>
      </WidgetShell>
    );
  }

  if (!ctResult || !ctResult.ok) {
    return (
      <WidgetShell title="Audit Status" icon={FileCheck}>
        <div aria-label="audit-status-unavailable">
          <SeverityIndicator severity="unknown" label="Chain status unavailable" />
          <p className="mt-1 text-xs text-muted">Control tower snapshot unavailable.</p>
        </div>
      </WidgetShell>
    );
  }

  const { status, first_bad, chain_head_hash } = ctResult.data.chain_integrity;
  const severity = mapToSeverity(status);

  return (
    <WidgetShell title="Audit Status" icon={FileCheck} ariaLabel="audit-status-widget">
      <SeverityIndicator severity={severity} label={status} />
      {first_bad && (
        <p className="mt-1 text-xs text-danger">Chain integrity issue detected.</p>
      )}
      {chain_head_hash && !first_bad && (
        <p
          className="mt-1.5 truncate font-mono text-[10px] text-muted"
          aria-label="chain-head-hash"
        >
          Head: {chain_head_hash.slice(0, 16)}…
        </p>
      )}
    </WidgetShell>
  );
}

function TenantSummaryWidget({
  ctResult,
  ctLoading,
}: {
  ctResult: SafeResult<ControlTowerSnapshotV1> | null;
  ctLoading: boolean;
}) {
  if (ctLoading) {
    return (
      <WidgetShell title="Tenant Context" icon={Users}>
        <div className="flex items-center gap-2 text-sm text-muted" aria-label="tenant-summary-loading">
          <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />
          Loading…
        </div>
      </WidgetShell>
    );
  }

  if (!ctResult || !ctResult.ok) {
    return (
      <WidgetShell title="Tenant Context" icon={Users}>
        <div aria-label="tenant-context-unavailable">
          <p className="text-sm text-muted">Tenant context unavailable</p>
          <p className="mt-0.5 text-xs text-muted/60">Control tower snapshot unavailable.</p>
        </div>
      </WidgetShell>
    );
  }

  const { tenant_id } = ctResult.data.tenant;
  const { effective_tenant_id, clamped } = ctResult.data.tenant.clamp;

  return (
    <WidgetShell title="Tenant Context" icon={Users} ariaLabel="tenant-summary-widget">
      <div aria-label="tenant-context-display">
        <p className="text-xs uppercase tracking-wide text-muted">Active Tenant</p>
        <p className="mt-0.5 truncate font-mono text-sm font-medium text-foreground">
          {tenant_id}
        </p>
        {clamped && effective_tenant_id !== tenant_id && (
          <p className="mt-1 text-[10px] text-warning">
            Clamped → {effective_tenant_id}
          </p>
        )}
        <p className="mt-2 text-[10px] text-muted/50">
          Display only — no switching authority
        </p>
      </div>
    </WidgetShell>
  );
}

function ProviderHealthWidget({
  ctResult,
  ctLoading,
}: {
  ctResult: SafeResult<ControlTowerSnapshotV1> | null;
  ctLoading: boolean;
}) {
  if (ctLoading) {
    return (
      <WidgetShell title="Provider Health" icon={Network}>
        <div className="flex items-center gap-2 text-sm text-muted" aria-label="provider-health-loading">
          <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />
          Loading…
        </div>
      </WidgetShell>
    );
  }

  if (!ctResult || !ctResult.ok) {
    return (
      <WidgetShell title="Provider Health" icon={Network}>
        <div aria-label="provider-health-unavailable">
          <p className="text-sm text-muted">Provider health not configured</p>
          <p className="mt-0.5 text-xs text-muted/60">Control tower snapshot unavailable.</p>
        </div>
      </WidgetShell>
    );
  }

  const { enabled, errors } = ctResult.data.connectors;
  const errorCount = errors.length;
  const connectorSeverity: Severity =
    errorCount > 0 ? 'warning' : enabled > 0 ? 'ok' : 'info';
  const connectorLabel =
    enabled === 0
      ? 'No connectors configured'
      : `${enabled} connector${enabled !== 1 ? 's' : ''} active`;

  return (
    <WidgetShell title="Provider Health" icon={Network} ariaLabel="provider-health-widget">
      <SeverityIndicator severity={connectorSeverity} label={connectorLabel} />
      {errorCount > 0 && (
        <p className="mt-1 text-xs text-warning" aria-label="provider-connector-errors">
          {errorCount} connector error{errorCount !== 1 ? 's' : ''}
        </p>
      )}
      {enabled === 0 && errorCount === 0 && (
        <p className="mt-1 text-xs text-muted">No AI providers are connected.</p>
      )}
    </WidgetShell>
  );
}

function ActiveAlertsWidget({
  ctResult,
  ctLoading,
}: {
  ctResult: SafeResult<ControlTowerSnapshotV1> | null;
  ctLoading: boolean;
}) {
  if (ctLoading) {
    return (
      <WidgetShell title="Active Alerts" icon={AlertTriangle}>
        <div className="flex items-center gap-2 text-sm text-muted" aria-label="active-alerts-loading">
          <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />
          Loading…
        </div>
      </WidgetShell>
    );
  }

  if (!ctResult || !ctResult.ok) {
    return (
      <WidgetShell title="Active Alerts" icon={AlertTriangle}>
        <div aria-label="active-alerts-unavailable">
          <p className="text-sm text-muted">Alert source unavailable</p>
          <p className="mt-0.5 text-xs text-muted/60">Control tower snapshot unavailable.</p>
        </div>
      </WidgetShell>
    );
  }

  const count = ctResult.data.audit_incidents.recent_events.length;

  if (count === 0) {
    return (
      <WidgetShell title="Active Alerts" icon={AlertTriangle} ariaLabel="active-alerts-widget">
        <div aria-label="active-alerts-empty">
          <SeverityIndicator severity="ok" label="No active alerts" />
          <p className="mt-1 text-xs text-muted">No recent audit incidents.</p>
        </div>
      </WidgetShell>
    );
  }

  return (
    <WidgetShell title="Active Alerts" icon={AlertTriangle} ariaLabel="active-alerts-widget">
      <div aria-label="active-alerts-present">
        <SeverityIndicator
          severity="warning"
          label={`${count} incident${count !== 1 ? 's' : ''}`}
        />
        <p className="mt-1 text-xs text-muted">Recent audit events detected.</p>
        <Link
          href="/dashboard/forensics"
          className="mt-2 inline-flex items-center gap-1 text-xs text-primary hover:underline"
        >
          View forensics <ArrowRight className="h-3 w-3" aria-hidden="true" />
        </Link>
      </div>
    </WidgetShell>
  );
}

function UnavailableMetricWidget({
  title,
  icon: Icon,
  reason,
  ariaLabel,
}: {
  title: string;
  icon: React.ComponentType<{ className?: string }>;
  reason: string;
  ariaLabel?: string;
}) {
  return (
    <WidgetShell title={title} icon={Icon} ariaLabel={ariaLabel}>
      <div aria-label="metric-not-configured">
        <SeverityIndicator severity="unknown" label="Not yet measured" />
        <p className="mt-1 text-xs text-muted">{reason}</p>
      </div>
    </WidgetShell>
  );
}

function FuturePlaceholderWidget({
  label,
  description,
}: {
  label: string;
  description: string;
}) {
  return (
    <Card className="border-dashed opacity-60">
      <CardContent className="pt-5">
        <div className="flex flex-col gap-1" aria-label="future-placeholder">
          <p className="text-xs font-medium text-muted">{label}</p>
          <p className="text-[10px] italic text-muted/60">{description}</p>
        </div>
      </CardContent>
    </Card>
  );
}

// ─── Stat card ────────────────────────────────────────────────────────────────

function StatCard({
  label,
  value,
  icon: Icon,
  delta,
  deltaLabel,
  variant = 'default',
}: {
  label: string;
  value: string | number;
  icon: React.ComponentType<{ className?: string }>;
  delta?: number;
  deltaLabel?: string;
  variant?: 'default' | 'danger' | 'success' | 'warning';
}) {
  const iconBg = {
    default: 'bg-primary/10 text-primary',
    danger: 'bg-danger/10 text-danger',
    success: 'bg-success/10 text-success',
    warning: 'bg-warning/10 text-warning',
  }[variant];

  return (
    <Card>
      <CardContent className="pt-5">
        <div className="flex items-start justify-between">
          <div>
            <p className="text-xs uppercase tracking-wide text-muted">{label}</p>
            <p className="mt-1.5 text-2xl font-bold text-foreground">{value}</p>
            {delta !== undefined && (
              <p className={`mt-1 text-xs ${delta >= 0 ? 'text-success' : 'text-danger'}`}>
                {delta >= 0 ? '+' : ''}{delta}% {deltaLabel}
              </p>
            )}
          </div>
          <div className={`flex h-9 w-9 items-center justify-center rounded-lg ${iconBg}`}>
            <Icon className="h-4 w-4" aria-hidden="true" />
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

// ─── Billing readiness panel ──────────────────────────────────────────────────

function BillingReadinessPanel({
  loading,
  result,
}: {
  loading: boolean;
  result: SafeResult<BillingReadiness> | null;
}) {
  if (loading) {
    return (
      <Card>
        <CardContent className="pt-5">
          <div className="flex items-center gap-2 text-sm text-muted" aria-label="billing-loading">
            <Loader2 className="h-4 w-4 animate-spin" />
            Loading billing status…
          </div>
        </CardContent>
      </Card>
    );
  }

  if (!result) return null;

  if (!result.ok) {
    return (
      <Card>
        <CardContent className="pt-5">
          <div className="flex items-center gap-2 text-sm text-danger" aria-label="billing-error">
            <AlertTriangle className="h-4 w-4 shrink-0" />
            Billing status unavailable — {result.error}
          </div>
        </CardContent>
      </Card>
    );
  }

  const { provider, ready, reasons } = result.data;

  if (ready) {
    return (
      <Card>
        <CardContent className="pt-5">
          <div className="flex items-center gap-2 text-sm text-success" aria-label="billing-ready">
            <CreditCard className="h-4 w-4 shrink-0" />
            Billing ready — provider: {provider}
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardContent className="pt-5">
        <div className="flex flex-col gap-2" aria-label="billing-not-ready">
          <div className="flex items-center gap-2 text-sm text-warning">
            <CreditCard className="h-4 w-4 shrink-0" />
            Billing not ready — provider: {provider}
          </div>
          {reasons.length > 0 && (
            <ul className="ml-6 space-y-0.5">
              {reasons.map((r) => (
                <li key={r} className="font-mono text-xs text-muted">
                  {r}
                </li>
              ))}
            </ul>
          )}
        </div>
      </CardContent>
    </Card>
  );
}

// ─── Recent events from feed ──────────────────────────────────────────────────

function severityToBadgeVariant(sev?: string | null): 'danger' | 'success' | 'secondary' {
  const s = (sev || '').toLowerCase();
  if (s === 'critical' || s === 'high') return 'danger';
  if (s === 'low') return 'success';
  return 'secondary';
}

function feedItemToLabel(item: FeedItem): string {
  return item.title || item.event_type || 'event';
}

function feedItemToLevel(item: FeedItem): string {
  const action = (item.action_taken || '').toLowerCase();
  if (action === 'blocked' || action === 'block') return 'blocked';
  return item.severity || 'info';
}

function relativeTime(ts?: string | null): string {
  if (!ts) return '';
  try {
    const diff = Date.now() - new Date(ts).getTime();
    const mins = Math.floor(diff / 60_000);
    if (mins < 1) return 'just now';
    if (mins < 60) return `${mins}m ago`;
    const hrs = Math.floor(mins / 60);
    if (hrs < 24) return `${hrs}h ago`;
    return `${Math.floor(hrs / 24)}d ago`;
  } catch {
    return '';
  }
}

function RecentEventsPanel({
  loading,
  result,
}: {
  loading: boolean;
  result: SafeResult<FeedLiveResponse> | null;
}) {
  if (loading) {
    return (
      <div className="flex items-center gap-2 py-4 text-sm text-muted" aria-label="events-loading">
        <Loader2 className="h-4 w-4 animate-spin" />
        Loading recent events…
      </div>
    );
  }

  if (!result) return null;

  if (!result.ok) {
    return (
      <div className="flex items-center gap-2 py-2 text-sm text-danger" aria-label="events-error">
        <AlertTriangle className="h-4 w-4 shrink-0" />
        Events unavailable — {result.error}
      </div>
    );
  }

  const items = result.data.items;

  if (items.length === 0) {
    return (
      <div className="py-4 text-center text-sm text-muted" aria-label="events-empty">
        No events yet — decisions will appear here once traffic flows through FrostGate.
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {items.map((ev) => {
        const level = feedItemToLevel(ev);
        return (
          <div
            key={ev.id}
            className="flex items-start gap-3 border-b border-border py-2 text-sm last:border-0"
          >
            <Badge
              variant={severityToBadgeVariant(ev.severity)}
              className="mt-0.5 shrink-0 text-[10px]"
            >
              {level}
            </Badge>
            <span className="flex-1 text-muted">{feedItemToLabel(ev)}</span>
            <span className="shrink-0 text-xs text-muted/60">{relativeTime(ev.timestamp)}</span>
          </div>
        );
      })}
    </div>
  );
}

// ─── Main page ────────────────────────────────────────────────────────────────

export default function DashboardOverviewPage() {
  // Core health + stats state
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [health, setHealth] = useState<HealthData | null>(null);
  const [loading, setLoading] = useState(true);
  const [coreError, setCoreError] = useState(false);

  // Billing readiness
  const [billingResult, setBillingResult] = useState<SafeResult<BillingReadiness> | null>(null);
  const [billingLoading, setBillingLoading] = useState(true);

  // Feed events
  const [feedResult, setFeedResult] = useState<SafeResult<FeedLiveResponse> | null>(null);
  const [feedLoading, setFeedLoading] = useState(true);
  const [chartData, setChartData] = useState<ChartPoint[]>([]);

  // Assessment domain scores (from sessionStorage)
  const [domainScores, setDomainScores] = useState<Record<string, number> | null>(null);

  // Command Center — control tower snapshot
  const [ctResult, setCtResult] = useState<SafeResult<ControlTowerSnapshotV1> | null>(null);
  const [ctLoading, setCtLoading] = useState(true);

  useEffect(() => {
    async function load() {
      try {
        const [healthRes, statsRes] = await Promise.all([
          fetch('/api/core/health/ready'),
          fetch('/api/core/stats/summary'),
        ]);
        if (healthRes.ok) {
          const h: HealthData = await healthRes.json();
          setHealth(h);
        }
        if (statsRes.ok) setStats(await statsRes.json());
      } catch {
        setCoreError(true);
      } finally {
        setLoading(false);
      }
    }
    load();
    const interval = setInterval(load, 30_000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    getBillingReadiness().then((r) => {
      setBillingResult(r);
      setBillingLoading(false);
    });
  }, []);

  useEffect(() => {
    getRecentFeedEvents(10).then((r) => {
      setFeedResult(r);
      setFeedLoading(false);

      if (r.ok && r.data.items.length > 0) {
        const buckets = new Map<string, { allowed: number; blocked: number }>();
        for (const item of r.data.items) {
          if (!item.timestamp) continue;
          try {
            const d = new Date(item.timestamp);
            const key = `${String(d.getHours()).padStart(2, '0')}:00`;
            const b = buckets.get(key) || { allowed: 0, blocked: 0 };
            const action = (item.action_taken || '').toLowerCase();
            if (action === 'blocked' || action === 'block') {
              b.blocked += 1;
            } else {
              b.allowed += 1;
            }
            buckets.set(key, b);
          } catch {
            // skip malformed timestamp
          }
        }
        const points: ChartPoint[] = Array.from(buckets.entries())
          .sort((a, b) => a[0].localeCompare(b[0]))
          .map(([time, v]) => ({ time, ...v }));
        if (points.length > 0) setChartData(points);
      }
    });
  }, []);

  useEffect(() => {
    try {
      const stored = sessionStorage.getItem('fg_last_assessment_scores');
      if (stored) {
        const parsed = JSON.parse(stored);
        if (parsed && typeof parsed === 'object') {
          setDomainScores(parsed as Record<string, number>);
        }
      }
    } catch {
      // sessionStorage unavailable or data corrupt — leave null
    }
  }, []);

  useEffect(() => {
    let cancelled = false;

    async function loadCt() {
      const result = await getCommandCenterSnapshot();
      if (!cancelled) {
        setCtResult(result);
        setCtLoading(false);
      }
    }

    loadCt();
    const interval = setInterval(loadCt, 60_000);
    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, []);

  const blockRate =
    stats && stats.total_requests > 0
      ? Math.round((stats.blocked_requests / stats.total_requests) * 100)
      : 0;

  return (
    <div className="flex flex-col">
      <TopBar
        title="Command Center"
        subtitle="AI governance operational overview"
        actions={
          <Link href="/onboarding">
            <Button size="sm" className="gap-1.5">
              <Plus className="h-3.5 w-3.5" /> New Assessment
            </Button>
          </Link>
        }
      />

      <div className="p-6 space-y-6">
        {/* Core status banner */}
        {!loading && (
          <div
            className={`flex items-center gap-3 rounded-lg border px-4 py-3 text-sm ${
              coreError
                ? 'border-danger/30 bg-danger/5 text-danger'
                : 'border-success/30 bg-success/5 text-success'
            }`}
            aria-label="core-status"
          >
            {coreError ? (
              <>
                <AlertTriangle className="h-4 w-4 shrink-0" />
                Core unreachable — check admin-gateway is running
              </>
            ) : (
              <>
                <CheckCircle2 className="h-4 w-4 shrink-0" />
                {health?.service ?? 'FrostGate Core'} v{health?.version} — all systems operational
              </>
            )}
          </div>
        )}

        {/* === Operational Status === */}
        <section aria-labelledby="cc-operational-heading">
          <h2
            id="cc-operational-heading"
            className="mb-3 text-[11px] font-semibold uppercase tracking-widest text-muted/60"
          >
            Operational Status
          </h2>
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
            <SystemHealthWidget health={health} loading={loading} coreError={coreError} />
            <RetrievalHealthWidget ctResult={ctResult} ctLoading={ctLoading} />
            <AuditStatusWidget ctResult={ctResult} ctLoading={ctLoading} />
          </div>
        </section>

        {/* === Governance & Tenancy === */}
        <section aria-labelledby="cc-governance-heading">
          <h2
            id="cc-governance-heading"
            className="mb-3 text-[11px] font-semibold uppercase tracking-widest text-muted/60"
          >
            Governance &amp; Tenancy
          </h2>
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
            <TenantSummaryWidget ctResult={ctResult} ctLoading={ctLoading} />
            <ProviderHealthWidget ctResult={ctResult} ctLoading={ctLoading} />
            <ActiveAlertsWidget ctResult={ctResult} ctLoading={ctLoading} />
          </div>
        </section>

        {/* === Quality Metrics (safe unavailable states) === */}
        <section aria-labelledby="cc-metrics-heading">
          <h2
            id="cc-metrics-heading"
            className="mb-3 text-[11px] font-semibold uppercase tracking-widest text-muted/60"
          >
            Quality Metrics
          </h2>
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
            <UnavailableMetricWidget
              title="Grounded Answer Rate"
              icon={TrendingUp}
              reason="No metric source configured — not yet measured."
              ariaLabel="grounded-answer-rate-widget"
            />
            <UnavailableMetricWidget
              title="Provenance Failures"
              icon={GitBranch}
              reason="No metric source configured — provenance failure rate unavailable."
              ariaLabel="provenance-failures-widget"
            />
            <UnavailableMetricWidget
              title="Readiness Summary"
              icon={FileCheck}
              reason="Readiness engine not configured."
              ariaLabel="readiness-summary-widget"
            />
          </div>
        </section>

        {/* === Future Capabilities === */}
        <section aria-labelledby="cc-future-heading">
          <h2
            id="cc-future-heading"
            className="mb-3 text-[11px] font-semibold uppercase tracking-widest text-muted/60"
          >
            Future Capabilities
          </h2>
          <div
            className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4"
            aria-label="future-placeholders"
          >
            <FuturePlaceholderWidget
              label="SLA Health"
              description="Not configured — no SLA target defined."
            />
            <FuturePlaceholderWidget
              label="Retrieval Latency"
              description="Not yet measured — no latency metric source."
            />
            <FuturePlaceholderWidget
              label="Hallucination Trends"
              description="Not yet measured — no evaluation source."
            />
            <FuturePlaceholderWidget
              label="Drift Metrics"
              description="Not configured — no drift detection source."
            />
          </div>
        </section>

        {/* === Platform Activity === */}
        <section aria-labelledby="cc-activity-heading">
          <h2
            id="cc-activity-heading"
            className="mb-3 text-[11px] font-semibold uppercase tracking-widest text-muted/60"
          >
            Platform Activity
          </h2>

          {/* Billing readiness */}
          <BillingReadinessPanel loading={billingLoading} result={billingResult} />

          {/* Stats row */}
          <div className="mt-4 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
            <StatCard
              label="Total Requests"
              value={loading ? '—' : (stats?.total_requests ?? 0).toLocaleString()}
              icon={Activity}
            />
            <StatCard
              label="Blocked"
              value={loading ? '—' : (stats?.blocked_requests ?? 0).toLocaleString()}
              icon={Shield}
              variant={blockRate > 10 ? 'warning' : 'default'}
              deltaLabel={`${blockRate}% block rate`}
            />
            <StatCard
              label="Active Tenants"
              value={loading ? '—' : (stats?.active_tenants ?? 0)}
              icon={Users}
              variant="success"
            />
            <StatCard
              label="Active API Keys"
              value={loading ? '—' : (stats?.active_keys ?? 0)}
              icon={Key}
            />
          </div>

          {/* Charts */}
          <div className="mt-4 grid gap-6 lg:grid-cols-2">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2 text-sm">
                  <TrendingUp className="h-4 w-4 text-primary" />
                  Request Volume (live feed)
                </CardTitle>
                <CardDescription>Allowed vs. blocked decisions from live feed</CardDescription>
              </CardHeader>
              <CardContent>
                {feedLoading ? (
                  <div className="flex items-center gap-2 py-4 text-sm text-muted" aria-label="chart-loading">
                    <Loader2 className="h-4 w-4 animate-spin" />
                    Loading chart data…
                  </div>
                ) : feedResult && !feedResult.ok ? (
                  <div className="flex items-center gap-2 py-4 text-sm text-danger" aria-label="chart-error">
                    <AlertTriangle className="h-4 w-4 shrink-0" />
                    Chart data unavailable — {feedResult.error}
                  </div>
                ) : chartData.length === 0 ? (
                  <div className="py-4 text-center text-sm text-muted" aria-label="chart-empty">
                    No traffic data yet — chart will populate as decisions flow through FrostGate.
                  </div>
                ) : (
                  <>
                    <RequestsChart data={chartData} />
                    <div className="mt-2 flex gap-4">
                      <span className="flex items-center gap-1.5 text-xs text-muted">
                        <span className="h-2 w-2 rounded-full bg-success" />
                        Allowed
                      </span>
                      <span className="flex items-center gap-1.5 text-xs text-muted">
                        <span className="h-2 w-2 rounded-full bg-danger" />
                        Blocked
                      </span>
                    </div>
                  </>
                )}
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2 text-sm">
                  <Shield className="h-4 w-4 text-primary" />
                  Risk Domain Scores
                </CardTitle>
                <CardDescription>Latest AI governance assessment scores across domains</CardDescription>
              </CardHeader>
              <CardContent>
                {domainScores ? (
                  <DomainScores scores={domainScores} />
                ) : (
                  <div
                    className="flex flex-col items-center gap-3 py-6 text-center"
                    aria-label="domain-scores-empty"
                  >
                    <FileText className="h-8 w-8 text-muted/40" />
                    <p className="text-sm text-muted">No assessment scores yet.</p>
                    <Link href="/onboarding">
                      <Button size="sm" variant="outline" className="gap-1.5">
                        <Plus className="h-3.5 w-3.5" /> Run Assessment
                      </Button>
                    </Link>
                  </div>
                )}
              </CardContent>
            </Card>
          </div>

          {/* Quick actions */}
          <div className="mt-4 grid gap-4 sm:grid-cols-3">
            <Link href="/onboarding" className="group">
              <Card className="cursor-pointer transition-colors hover:border-primary/40">
                <CardContent className="flex items-center justify-between pt-5">
                  <div>
                    <p className="text-sm font-medium text-foreground">Run Assessment</p>
                    <p className="mt-0.5 text-xs text-muted">AI governance risk scoring</p>
                  </div>
                  <ArrowRight className="h-4 w-4 text-muted transition-colors group-hover:text-primary" />
                </CardContent>
              </Card>
            </Link>

            <Link href="/reports" className="group">
              <Card className="cursor-pointer transition-colors hover:border-primary/40">
                <CardContent className="flex items-center justify-between pt-5">
                  <div>
                    <p className="text-sm font-medium text-foreground">View Reports</p>
                    <p className="mt-0.5 text-xs text-muted">AI-generated advisory reports</p>
                  </div>
                  <ArrowRight className="h-4 w-4 text-muted transition-colors group-hover:text-primary" />
                </CardContent>
              </Card>
            </Link>

            <Link href="/audit" className="group">
              <Card className="cursor-pointer transition-colors hover:border-primary/40">
                <CardContent className="flex items-center justify-between pt-5">
                  <div>
                    <p className="text-sm font-medium text-foreground">Audit Log</p>
                    <p className="mt-0.5 text-xs text-muted">HMAC-chained forensic trail</p>
                  </div>
                  <ArrowRight className="h-4 w-4 text-muted transition-colors group-hover:text-primary" />
                </CardContent>
              </Card>
            </Link>
          </div>

          {/* Recent events */}
          <Card className="mt-4">
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-sm">
                <Clock className="h-4 w-4 text-primary" />
                Recent Events
              </CardTitle>
              <CardDescription>Live decision feed from FrostGate core</CardDescription>
            </CardHeader>
            <CardContent>
              <RecentEventsPanel loading={feedLoading} result={feedResult} />
            </CardContent>
          </Card>
        </section>
      </div>
    </div>
  );
}
