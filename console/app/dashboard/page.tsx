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
} from 'lucide-react';
import { TopBar } from '@/components/layout/TopBar';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { DomainScores } from '@/components/dashboard/DomainScores';
import { RequestsChart } from '@/components/dashboard/RequestsChart';

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
}

// ─── Mock chart data (replaced by real API data when available) ───────────────

const MOCK_CHART_DATA = Array.from({ length: 12 }, (_, i) => ({
  time: `${String(i * 2).padStart(2, '0')}:00`,
  allowed: Math.floor(Math.random() * 800 + 200),
  blocked: Math.floor(Math.random() * 80 + 10),
}));

const MOCK_DOMAIN_SCORES = {
  data_governance: 42,
  security_posture: 61,
  ai_maturity: 35,
  infra_readiness: 58,
  compliance_awareness: 47,
  automation_potential: 72,
};

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

// ─── Main page ────────────────────────────────────────────────────────────────

export default function DashboardOverviewPage() {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [health, setHealth] = useState<HealthData | null>(null);
  const [loading, setLoading] = useState(true);
  const [coreError, setCoreError] = useState(false);

  useEffect(() => {
    async function load() {
      try {
        const [healthRes, statsRes] = await Promise.all([
          fetch('/api/core/health/ready'),
          fetch('/api/core/stats/summary'),
        ]);
        if (healthRes.ok) setHealth(await healthRes.json());
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

        {/* Stats row */}
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <StatCard
            label="Total Requests"
            value={loading ? '—' : (stats?.total_requests ?? 0).toLocaleString()}
            icon={Activity}
            delta={12}
            deltaLabel="vs last 24h"
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
                Request Volume (24h)
              </CardTitle>
              <CardDescription>Allowed vs. blocked AI requests over time</CardDescription>
            </CardHeader>
            <CardContent>
              <RequestsChart data={MOCK_CHART_DATA} />
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
              <DomainScores scores={MOCK_DOMAIN_SCORES} />
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

        {/* Recent events placeholder */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-sm">
              <Clock className="h-4 w-4 text-primary" />
              Recent Events
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              {[
                { msg: 'PHI detected — request blocked before Anthropic boundary', level: 'blocked', time: '2m ago' },
                { msg: 'Assessment completed — Apex National Bank, score 47/100', level: 'info', time: '18m ago' },
                { msg: 'New API key issued — tenant: meridian-health', level: 'info', time: '1h ago' },
                { msg: 'Policy update deployed — hipaa.rego v2.1', level: 'success', time: '3h ago' },
              ].map((ev, i) => (
                <div key={i} className="flex items-start gap-3 text-sm py-2 border-b border-border last:border-0">
                  <Badge
                    variant={
                      ev.level === 'blocked'
                        ? 'danger'
                        : ev.level === 'success'
                        ? 'success'
                        : 'secondary'
                    }
                    className="text-[10px] shrink-0 mt-0.5"
                  >
                    {ev.level}
                  </Badge>
                  <span className="flex-1 text-muted">{ev.msg}</span>
                  <span className="text-xs text-muted/60 shrink-0">{ev.time}</span>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
