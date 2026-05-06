'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';
import {
  Activity,
  Shield,
  Users,
  Key,
  TrendingUp,
  AlertTriangle,
  CheckCircle2,
  Clock,
  ArrowRight,
  Zap,
  CreditCard,
  FileText,
  Loader2,
} from 'lucide-react';
import { TopBar } from '@/components/layout/TopBar';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { DomainScores } from '@/components/dashboard/DomainScores';
import { RequestsChart } from '@/components/dashboard/RequestsChart';
import {
  getBillingReadiness,
  getRecentFeedEvents,
  type BillingReadiness,
  type FeedItem,
  type SafeResult,
  type FeedLiveResponse,
} from '@/lib/coreApi';

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
}

interface ChartPoint {
  time: string;
  allowed: number;
  blocked: number;
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
            <p className="text-xs text-muted uppercase tracking-wide">{label}</p>
            <p className="mt-1.5 text-2xl font-bold text-foreground">{value}</p>
            {delta !== undefined && (
              <p className={`mt-1 text-xs ${delta >= 0 ? 'text-success' : 'text-danger'}`}>
                {delta >= 0 ? '+' : ''}{delta}% {deltaLabel}
              </p>
            )}
          </div>
          <div className={`flex h-9 w-9 items-center justify-center rounded-lg ${iconBg}`}>
            <Icon className="h-4 w-4" />
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
                <li key={r} className="text-xs text-muted font-mono">
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
  const sev = (item.severity || '').toLowerCase();
  if (sev === 'critical' || sev === 'high') return 'blocked';
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
      <div className="flex items-center gap-2 text-sm text-muted py-4" aria-label="events-loading">
        <Loader2 className="h-4 w-4 animate-spin" />
        Loading recent events…
      </div>
    );
  }

  if (!result) return null;

  if (!result.ok) {
    return (
      <div className="flex items-center gap-2 text-sm text-danger py-2" aria-label="events-error">
        <AlertTriangle className="h-4 w-4 shrink-0" />
        Events unavailable — {result.error}
      </div>
    );
  }

  const items = result.data.items;

  if (items.length === 0) {
    return (
      <div className="text-sm text-muted py-4 text-center" aria-label="events-empty">
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
            className="flex items-start gap-3 text-sm py-2 border-b border-border last:border-0"
          >
            <Badge
              variant={severityToBadgeVariant(ev.severity)}
              className="text-[10px] shrink-0 mt-0.5"
            >
              {level}
            </Badge>
            <span className="flex-1 text-muted">{feedItemToLabel(ev)}</span>
            <span className="text-xs text-muted/60 shrink-0">{relativeTime(ev.timestamp)}</span>
          </div>
        );
      })}
    </div>
  );
}

// ─── Main page ────────────────────────────────────────────────────────────────

export default function DashboardOverviewPage() {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [health, setHealth] = useState<HealthData | null>(null);
  const [loading, setLoading] = useState(true);
  const [coreError, setCoreError] = useState(false);

  const [billingResult, setBillingResult] = useState<SafeResult<BillingReadiness> | null>(null);
  const [billingLoading, setBillingLoading] = useState(true);

  const [feedResult, setFeedResult] = useState<SafeResult<FeedLiveResponse> | null>(null);
  const [feedLoading, setFeedLoading] = useState(true);

  // Chart data derived from feed (allowed/blocked per feed batch, placeholder if no data)
  const [chartData, setChartData] = useState<ChartPoint[]>([]);

  // Domain scores from latest scored assessment (null = not yet available)
  const [domainScores, setDomainScores] = useState<Record<string, number> | null>(null);

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
        // Build a compact chart from feed items: group by rounded hour
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

  // Pull domain scores from the last scored assessment stored in sessionStorage
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

  const blockRate =
    stats && stats.total_requests > 0
      ? Math.round((stats.blocked_requests / stats.total_requests) * 100)
      : 0;

  return (
    <div className="flex flex-col">
      <TopBar
        title="Dashboard"
        subtitle="AI governance overview"
        actions={
          <Link href="/onboarding">
            <Button size="sm" className="gap-1.5">
              <Zap className="h-3.5 w-3.5" /> New Assessment
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

        {/* Billing readiness */}
        <BillingReadinessPanel loading={billingLoading} result={billingResult} />

        {/* Stats row */}
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
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
        <div className="grid gap-6 lg:grid-cols-2">
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
                <div className="flex items-center gap-2 text-sm text-muted py-4" aria-label="chart-loading">
                  <Loader2 className="h-4 w-4 animate-spin" />
                  Loading chart data…
                </div>
              ) : chartData.length === 0 ? (
                <div className="text-sm text-muted py-4 text-center" aria-label="chart-empty">
                  No traffic data yet — chart will populate as decisions flow through FrostGate.
                </div>
              ) : (
                <>
                  <RequestsChart data={chartData} />
                  <div className="flex gap-4 mt-2">
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
                  <p className="text-sm text-muted">
                    No assessment scores yet.
                  </p>
                  <Link href="/onboarding">
                    <Button size="sm" variant="outline" className="gap-1.5">
                      <Zap className="h-3.5 w-3.5" /> Run Assessment
                    </Button>
                  </Link>
                </div>
              )}
            </CardContent>
          </Card>
        </div>

        {/* Quick actions */}
        <div className="grid gap-4 sm:grid-cols-3">
          <Link href="/onboarding" className="group">
            <Card className="hover:border-primary/40 transition-colors cursor-pointer">
              <CardContent className="pt-5 flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-foreground">Run Assessment</p>
                  <p className="text-xs text-muted mt-0.5">AI governance risk scoring</p>
                </div>
                <ArrowRight className="h-4 w-4 text-muted group-hover:text-primary transition-colors" />
              </CardContent>
            </Card>
          </Link>

          <Link href="/reports" className="group">
            <Card className="hover:border-primary/40 transition-colors cursor-pointer">
              <CardContent className="pt-5 flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-foreground">View Reports</p>
                  <p className="text-xs text-muted mt-0.5">AI-generated advisory reports</p>
                </div>
                <ArrowRight className="h-4 w-4 text-muted group-hover:text-primary transition-colors" />
              </CardContent>
            </Card>
          </Link>

          <Link href="/audit" className="group">
            <Card className="hover:border-primary/40 transition-colors cursor-pointer">
              <CardContent className="pt-5 flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-foreground">Audit Log</p>
                  <p className="text-xs text-muted mt-0.5">HMAC-chained forensic trail</p>
                </div>
                <ArrowRight className="h-4 w-4 text-muted group-hover:text-primary transition-colors" />
              </CardContent>
            </Card>
          </Link>
        </div>

        {/* Recent events from live feed */}
        <Card>
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
      </div>
    </div>
  );
}
