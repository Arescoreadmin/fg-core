'use client';

import { useEffect, useRef, useState } from 'react';
import {
  Activity,
  AlertTriangle,
  BarChart3,
  Brain,
  Building2,
  CheckCircle,
  Clock,
  FileText,
  Loader2,
  Shield,
  Target,
  TrendingUp,
  Zap,
} from 'lucide-react';
import { TopBar } from '@/components/layout/TopBar';
import {
  getExecutiveBusiness,
  getExecutiveCompliance,
  getExecutiveForecast,
  getExecutiveOverview,
  getExecutiveRecommendations,
  getExecutiveRisk,
  getExecutiveSummary,
  getExecutiveTrends,
  getExecutiveWorkspace,
  type ExecutiveBusiness,
  type ExecutiveCompliance,
  type ExecutiveForecast,
  type ExecutiveOverview,
  type ExecutiveRecommendations,
  type ExecutiveRisk,
  type ExecutiveSummary,
  type ExecutiveTrends,
  type ExecutiveWorkspace,
} from '@/lib/executiveApi';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

type TrendWindow = '30d' | '90d' | '180d' | '365d';

type TabId =
  | 'overview'
  | 'risk'
  | 'compliance'
  | 'trends'
  | 'business'
  | 'recommendations'
  | 'forecast'
  | 'board';

const TABS: { id: TabId; label: string }[] = [
  { id: 'overview', label: 'Overview' },
  { id: 'risk', label: 'Risk' },
  { id: 'compliance', label: 'Compliance' },
  { id: 'trends', label: 'Trends' },
  { id: 'business', label: 'Business' },
  { id: 'recommendations', label: 'Recommendations' },
  { id: 'forecast', label: 'Forecast' },
  { id: 'board', label: 'Board Summary' },
];

function scoreColor(score: number): string {
  if (score >= 80) return 'text-green-400';
  if (score >= 60) return 'text-yellow-400';
  return 'text-red-400';
}

function scoreBadge(score: number): string {
  if (score >= 80) return 'bg-green-500/10 text-green-400 border border-green-500/20';
  if (score >= 60) return 'bg-yellow-500/10 text-yellow-400 border border-yellow-500/20';
  return 'bg-red-500/10 text-red-400 border border-red-500/20';
}

function severityBadge(sev: string): string {
  switch (sev) {
    case 'critical': return 'bg-red-500/10 text-red-400 border border-red-500/20';
    case 'high':     return 'bg-orange-500/10 text-orange-400 border border-orange-500/20';
    case 'medium':   return 'bg-yellow-500/10 text-yellow-400 border border-yellow-500/20';
    default:         return 'bg-blue-500/10 text-blue-400 border border-blue-500/20';
  }
}

function trendArrow(trend: string): string {
  if (trend === 'improving') return '↑';
  if (trend === 'degrading') return '↓';
  return '→';
}

function trendColor(trend: string): string {
  if (trend === 'improving') return 'text-green-400';
  if (trend === 'degrading') return 'text-red-400';
  return 'text-muted-foreground';
}

function fmtUsd(val: number | null): string {
  if (val === null) return '—';
  if (val >= 1_000_000) return `$${(val / 1_000_000).toFixed(1)}M`;
  if (val >= 1_000) return `$${(val / 1_000).toFixed(0)}K`;
  return `$${val}`;
}

function fmtPct(val: number | null): string {
  if (val === null) return '—';
  return `${val.toFixed(1)}%`;
}

function fmtConfidence(val: number): string {
  return `${Math.round(val * 100)}%`;
}

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------

function MetricTile({
  label,
  value,
  sub,
  icon: Icon,
  valueClass,
}: {
  label: string;
  value: string;
  sub?: string;
  icon: React.ElementType;
  valueClass?: string;
}) {
  return (
    <div className="bg-surface border border-border rounded-lg p-4 flex flex-col gap-2">
      <div className="flex items-center gap-2 text-muted-foreground">
        <Icon className="h-4 w-4" aria-hidden="true" />
        <span className="text-xs">{label}</span>
      </div>
      <span className={`text-2xl font-semibold ${valueClass ?? 'text-foreground'}`}>{value}</span>
      {sub && <span className="text-xs text-muted-foreground">{sub}</span>}
    </div>
  );
}

function SectionCard({ children, className }: { children: React.ReactNode; className?: string }) {
  return (
    <div className={`bg-surface border border-border rounded-lg p-6 ${className ?? ''}`}>
      {children}
    </div>
  );
}

function LoadingRow() {
  return (
    <div className="flex items-center gap-2 text-sm text-muted-foreground py-4">
      <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />
      Loading…
    </div>
  );
}

function ErrorRow({ msg }: { msg: string }) {
  return (
    <p className="text-sm text-red-400 py-4">{msg}</p>
  );
}

// ---------------------------------------------------------------------------
// Tab content components
// ---------------------------------------------------------------------------

function OverviewTab({ initialData }: { initialData?: ExecutiveOverview }) {
  const [loading, setLoading] = useState(!initialData);
  const [data, setData] = useState<ExecutiveOverview | null>(initialData ?? null);
  const [error, setError] = useState<string | null>(null);
  const hasInitialRef = useRef(Boolean(initialData));

  useEffect(() => {
    if (hasInitialRef.current) return;
    let cancelled = false;
    getExecutiveOverview().then((r) => {
      if (cancelled) return;
      setLoading(false);
      if (!r.ok) { setError(r.error); return; }
      setData(r.data);
    });
    return () => { cancelled = true; };
  }, []);

  if (loading) return <LoadingRow />;
  if (error) return <ErrorRow msg={error} />;
  if (!data) return null;

  return (
    <div className="flex flex-col gap-6">
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-3 lg:grid-cols-4 xl:grid-cols-5">
        <MetricTile
          label="Governance Health"
          value={`${data.governance_health_score}/100`}
          icon={Shield}
          valueClass={scoreColor(data.governance_health_score)}
        />
        <MetricTile
          label="Compliance Score"
          value={`${data.compliance_score}%`}
          icon={CheckCircle}
          valueClass={scoreColor(data.compliance_score)}
        />
        <MetricTile
          label="Risk Score"
          value={`${data.risk_score}/100`}
          sub="Higher = more risk"
          icon={AlertTriangle}
          valueClass={data.risk_score >= 70 ? 'text-red-400' : data.risk_score >= 40 ? 'text-yellow-400' : 'text-green-400'}
        />
        <MetricTile
          label="Identity Health"
          value={`${data.identity_health_score}/100`}
          icon={Activity}
          valueClass={scoreColor(data.identity_health_score)}
        />
        <MetricTile
          label="Evidence Freshness"
          value={`${data.evidence_freshness_score}%`}
          icon={Clock}
          valueClass={scoreColor(data.evidence_freshness_score)}
        />
        <MetricTile
          label="Control Coverage"
          value={`${data.control_coverage_pct}%`}
          icon={Target}
          valueClass={scoreColor(data.control_coverage_pct)}
        />
        <MetricTile
          label="Open Findings"
          value={String(data.open_findings_count)}
          icon={BarChart3}
          valueClass={data.open_findings_count > 0 ? 'text-yellow-400' : 'text-green-400'}
        />
        <MetricTile
          label="Critical Findings"
          value={String(data.critical_findings_count)}
          icon={AlertTriangle}
          valueClass={data.critical_findings_count > 0 ? 'text-red-400' : 'text-green-400'}
        />
        <MetricTile
          label="Automation Coverage"
          value={`${data.automation_coverage_pct}%`}
          icon={Zap}
          valueClass={scoreColor(data.automation_coverage_pct)}
        />
      </div>

      <SectionCard>
        <div className="flex items-center gap-2 mb-3">
          <Brain className="h-4 w-4 text-muted-foreground" aria-hidden="true" />
          <h2 className="text-sm font-semibold text-foreground">Executive Summary</h2>
          <span className={`ml-auto text-xs px-2 py-0.5 rounded-full ${scoreBadge(Math.round(data.confidence * 100))}`}>
            Confidence {fmtConfidence(data.confidence)}
          </span>
        </div>
        <p className="text-sm text-muted-foreground leading-relaxed">{data.executive_summary}</p>
        <div className="mt-3 flex gap-4 text-xs text-muted-foreground">
          <span>Source: {data.source}</span>
          <span>Window: {data.data_window_days}d</span>
          <span>Computed: {new Date(data.computed_at).toLocaleString()}</span>
        </div>
      </SectionCard>
    </div>
  );
}

function RiskTab({ initialData }: { initialData?: ExecutiveRisk }) {
  const [loading, setLoading] = useState(!initialData);
  const [data, setData] = useState<ExecutiveRisk | null>(initialData ?? null);
  const [error, setError] = useState<string | null>(null);
  const hasInitialRef = useRef(Boolean(initialData));

  useEffect(() => {
    if (hasInitialRef.current) return;
    let cancelled = false;
    getExecutiveRisk().then((r) => {
      if (cancelled) return;
      setLoading(false);
      if (!r.ok) { setError(r.error); return; }
      setData(r.data);
    });
    return () => { cancelled = true; };
  }, []);

  if (loading) return <LoadingRow />;
  if (error) return <ErrorRow msg={error} />;
  if (!data) return null;

  const severities = ['critical', 'high', 'medium', 'low'];

  return (
    <div className="flex flex-col gap-6">
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        {severities.map((sev) => (
          <SectionCard key={sev}>
            <div className="text-xs text-muted-foreground capitalize mb-1">{sev} findings</div>
            <div className={`text-2xl font-semibold ${sev === 'critical' ? 'text-red-400' : sev === 'high' ? 'text-orange-400' : sev === 'medium' ? 'text-yellow-400' : 'text-blue-400'}`}>
              {data.open_findings_by_severity[sev] ?? 0}
            </div>
          </SectionCard>
        ))}
      </div>

      <SectionCard>
        <h2 className="text-sm font-semibold text-foreground mb-4">Risk Breakdown by Severity</h2>
        <div className="flex flex-col gap-3">
          {data.heatmap.map((cell) => (
            <div key={cell.severity} className="flex items-center gap-3">
              <span className={`text-xs capitalize w-16 shrink-0 ${cell.severity === 'critical' ? 'text-red-400' : cell.severity === 'high' ? 'text-orange-400' : cell.severity === 'medium' ? 'text-yellow-400' : 'text-muted-foreground'}`}>
                {cell.severity}
              </span>
              <div className="flex-1 bg-border rounded-full h-2">
                <div
                  className={`h-2 rounded-full ${cell.severity === 'critical' ? 'bg-red-500' : cell.severity === 'high' ? 'bg-orange-500' : cell.severity === 'medium' ? 'bg-yellow-500' : 'bg-blue-500'}`}
                  style={{ width: `${Math.min(100, cell.count * 10)}%` }}
                />
              </div>
              <span className="text-xs text-foreground w-6 text-right">{cell.count}</span>
            </div>
          ))}
        </div>
        <div className="mt-3 flex gap-4 text-xs text-muted-foreground">
          <span>Source: {data.source}</span>
          <span>Risk score: {data.risk_score}/100</span>
          <span className={trendColor(data.risk_trend)}>{trendArrow(data.risk_trend)} {data.risk_trend}</span>
        </div>
      </SectionCard>

      <SectionCard>
        <h2 className="text-sm font-semibold text-foreground mb-4">Top Emerging Risks</h2>
        {data.top_risks.length === 0 ? (
          <p className="text-sm text-muted-foreground">No risks reported.</p>
        ) : (
          <div className="flex flex-col gap-3">
            {data.top_risks.slice(0, 5).map((risk, i) => (
              <div key={risk.risk_id} className="flex items-start gap-3 border-t border-border pt-3 first:border-0 first:pt-0">
                <span className="text-xs text-muted-foreground w-5 shrink-0 mt-0.5">{i + 1}.</span>
                <div className="flex flex-col gap-1 flex-1">
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-medium text-foreground">{risk.title}</span>
                    <span className={`text-xs px-1.5 py-0.5 rounded capitalize ${severityBadge(risk.severity)}`}>{risk.severity}</span>
                  </div>
                  <p className="text-xs text-muted-foreground">{risk.description}</p>
                  <div className="flex gap-3 text-xs text-muted-foreground">
                    <span>Category: {risk.category}</span>
                    <span>Likelihood: {risk.likelihood.replace('_', ' ')}</span>
                    <span>Evidence: {risk.evidence_count}</span>
                    {risk.owner && <span>Owner: {risk.owner}</span>}
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </SectionCard>
    </div>
  );
}

const FRAMEWORK_ORDER = ['NIST AI RMF', 'ISO 42001', 'SOC 2', 'HIPAA', 'PCI DSS', 'CIS Controls'];

function ComplianceTab({ initialData }: { initialData?: ExecutiveCompliance }) {
  const [loading, setLoading] = useState(!initialData);
  const [data, setData] = useState<ExecutiveCompliance | null>(initialData ?? null);
  const [error, setError] = useState<string | null>(null);
  const hasInitialRef = useRef(Boolean(initialData));

  useEffect(() => {
    if (hasInitialRef.current) return;
    let cancelled = false;
    getExecutiveCompliance().then((r) => {
      if (cancelled) return;
      setLoading(false);
      if (!r.ok) { setError(r.error); return; }
      setData(r.data);
    });
    return () => { cancelled = true; };
  }, []);

  if (loading) return <LoadingRow />;
  if (error) return <ErrorRow msg={error} />;
  if (!data) return null;

  const sorted = [...data.frameworks].sort(
    (a, b) => FRAMEWORK_ORDER.indexOf(a.framework_name) - FRAMEWORK_ORDER.indexOf(b.framework_name),
  );

  return (
    <div className="flex flex-col gap-6">
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        <SectionCard>
          <div className="text-xs text-muted-foreground mb-1">Overall Score</div>
          <div className={`text-2xl font-semibold ${scoreColor(data.overall_compliance_score)}`}>
            {data.overall_compliance_score}%
          </div>
        </SectionCard>
        <SectionCard>
          <div className="text-xs text-muted-foreground mb-1">Frameworks at Risk</div>
          <div className={`text-2xl font-semibold ${data.frameworks_at_risk > 0 ? 'text-red-400' : 'text-green-400'}`}>
            {data.frameworks_at_risk}
          </div>
        </SectionCard>
        <SectionCard>
          <div className="text-xs text-muted-foreground mb-1">Total Gaps</div>
          <div className={`text-2xl font-semibold ${data.total_gaps > 0 ? 'text-yellow-400' : 'text-green-400'}`}>
            {data.total_gaps}
          </div>
        </SectionCard>
        <SectionCard>
          <div className="text-xs text-muted-foreground mb-1">Data Confidence</div>
          <div className="text-2xl font-semibold text-foreground">{fmtConfidence(data.confidence)}</div>
        </SectionCard>
      </div>

      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {sorted.map((fw) => (
          <SectionCard key={fw.framework_id}>
            <div className="flex items-start justify-between gap-2 mb-3">
              <h3 className="text-sm font-semibold text-foreground">{fw.framework_name}</h3>
              <span className={`text-xs px-1.5 py-0.5 rounded ${trendColor(fw.trend)}`}>
                {trendArrow(fw.trend)} {fw.trend}
              </span>
            </div>
            <div className="flex flex-col gap-2">
              <div className="flex items-center justify-between">
                <span className="text-xs text-muted-foreground">Coverage</span>
                <span className={`text-sm font-semibold ${scoreColor(fw.coverage_pct)}`}>{fw.coverage_pct}%</span>
              </div>
              <div className="w-full bg-border rounded-full h-1.5">
                <div
                  className={`h-1.5 rounded-full ${fw.coverage_pct >= 80 ? 'bg-green-500' : fw.coverage_pct >= 60 ? 'bg-yellow-500' : 'bg-red-500'}`}
                  style={{ width: `${fw.coverage_pct}%` }}
                />
              </div>
              <div className="flex gap-3 text-xs text-muted-foreground mt-1">
                <span>Gaps: {fw.gap_count}</span>
                <span>Confidence: {fmtConfidence(fw.confidence)}</span>
              </div>
              {fw.last_assessed_at && (
                <div className="text-xs text-muted-foreground">
                  Last assessed: {new Date(fw.last_assessed_at).toLocaleDateString()}
                </div>
              )}
            </div>
          </SectionCard>
        ))}
      </div>

      <div className="text-xs text-muted-foreground">Source: {data.source} · Computed: {new Date(data.computed_at).toLocaleString()}</div>
    </div>
  );
}

function TrendsTab({ initialData }: { initialData?: ExecutiveTrends }) {
  const [loading, setLoading] = useState(false);
  const [data, setData] = useState<ExecutiveTrends | null>(initialData ?? null);
  const [error, setError] = useState<string | null>(null);
  const [trendWindow, setTrendWindow] = useState<TrendWindow>('90d');
  const hasInitialRef = useRef(Boolean(initialData));

  useEffect(() => {
    // Skip re-fetch for default 90d window when workspace pre-loaded it
    if (trendWindow === '90d' && hasInitialRef.current) return;
    let cancelled = false;
    setLoading(true);
    setData(null);
    getExecutiveTrends(trendWindow).then((r) => {
      if (cancelled) return;
      setLoading(false);
      if (!r.ok) { setError(r.error); return; }
      setData(r.data);
    });
    return () => { cancelled = true; };
  }, [trendWindow]);

  const WINDOWS: TrendWindow[] = ['30d', '90d', '180d', '365d'];

  const SERIES = [
    { key: 'governance_trend' as const, label: 'Governance', icon: Shield, color: 'text-blue-400' },
    { key: 'compliance_trend' as const, label: 'Compliance', icon: CheckCircle, color: 'text-green-400' },
    { key: 'risk_trend' as const, label: 'Risk', icon: AlertTriangle, color: 'text-orange-400' },
    { key: 'identity_trend' as const, label: 'Identity', icon: Activity, color: 'text-purple-400' },
  ];

  return (
    <div className="flex flex-col gap-6">
      <div className="flex items-center gap-2">
        <span className="text-xs text-muted-foreground">Window:</span>
        {WINDOWS.map((w) => (
          <button
            key={w}
            onClick={() => setTrendWindow(w)}
            className={`px-3 py-1 text-xs rounded border transition-colors ${
              trendWindow === w
                ? 'bg-primary text-primary-foreground border-primary'
                : 'bg-surface text-muted-foreground border-border hover:border-primary/50'
            }`}
          >
            {w}
          </button>
        ))}
      </div>

      {loading && <LoadingRow />}
      {error && <ErrorRow msg={error} />}

      {data && (
        <>
          <div className="grid gap-4 sm:grid-cols-2">
            {SERIES.map(({ key, label, icon: Icon, color }) => {
              const points = data[key];
              const latest = points.at(-1)?.value;
              const first = points.at(0)?.value;
              const delta = latest !== undefined && first !== undefined ? latest - first : null;
              return (
                <SectionCard key={key}>
                  <div className="flex items-center gap-2 mb-3">
                    <Icon className={`h-4 w-4 ${color}`} aria-hidden="true" />
                    <h3 className="text-sm font-semibold text-foreground">{label}</h3>
                    {delta !== null && (
                      <span className={`ml-auto text-xs ${delta > 0 ? 'text-green-400' : delta < 0 ? 'text-red-400' : 'text-muted-foreground'}`}>
                        {delta > 0 ? '+' : ''}{delta.toFixed(1)} over {trendWindow}
                      </span>
                    )}
                  </div>
                  {points.length === 0 ? (
                    <p className="text-xs text-muted-foreground">No data for this window.</p>
                  ) : (
                    <div className="flex flex-col gap-1">
                      {points.slice(-8).map((pt) => (
                        <div key={pt.date} className="flex items-center gap-2 text-xs">
                          <span className="text-muted-foreground w-20 shrink-0">{new Date(pt.date).toLocaleDateString()}</span>
                          <div className="flex-1 bg-border rounded-full h-1.5">
                            <div
                              className={`h-1.5 rounded-full ${color.replace('text-', 'bg-')}`}
                              style={{ width: `${Math.min(pt.value, 100)}%` }}
                            />
                          </div>
                          <span className="text-foreground w-10 text-right">{pt.value.toFixed(0)}</span>
                        </div>
                      ))}
                    </div>
                  )}
                </SectionCard>
              );
            })}
          </div>
          <div className="text-xs text-muted-foreground">Source: {data.source} · Computed: {new Date(data.computed_at).toLocaleString()}</div>
        </>
      )}
    </div>
  );
}

function BusinessTab({ initialData }: { initialData?: ExecutiveBusiness }) {
  const [loading, setLoading] = useState(!initialData);
  const [data, setData] = useState<ExecutiveBusiness | null>(initialData ?? null);
  const [error, setError] = useState<string | null>(null);
  const hasInitialRef = useRef(Boolean(initialData));

  useEffect(() => {
    if (hasInitialRef.current) return;
    let cancelled = false;
    getExecutiveBusiness().then((r) => {
      if (cancelled) return;
      setLoading(false);
      if (!r.ok) { setError(r.error); return; }
      setData(r.data);
    });
    return () => { cancelled = true; };
  }, []);

  if (loading) return <LoadingRow />;
  if (error) return <ErrorRow msg={error} />;
  if (!data) return null;

  const metrics = [
    { label: 'Cost of Risk Estimate', value: fmtUsd(data.cost_of_risk_estimate_usd), icon: Building2 },
    { label: 'Regulatory Exposure', value: fmtUsd(data.regulatory_exposure_usd), icon: FileText },
    { label: 'Business Continuity', value: `${data.business_continuity_score}/100`, icon: Shield, cls: scoreColor(data.business_continuity_score) },
    { label: 'Insurance Readiness', value: `${data.insurance_readiness_score}/100`, icon: CheckCircle, cls: scoreColor(data.insurance_readiness_score) },
    { label: 'Audit Readiness', value: `${data.audit_readiness_score}/100`, icon: Target, cls: scoreColor(data.audit_readiness_score) },
    { label: 'Expected Remediation Cost', value: fmtUsd(data.expected_remediation_cost_usd), icon: TrendingUp },
    { label: 'Revenue at Risk', value: fmtPct(data.revenue_at_risk_pct), icon: AlertTriangle, cls: data.revenue_at_risk_pct !== null && data.revenue_at_risk_pct > 5 ? 'text-red-400' : 'text-foreground' },
  ];

  return (
    <div className="flex flex-col gap-6">
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-3 lg:grid-cols-4">
        {metrics.map(({ label, value, icon: Icon, cls }) => (
          <MetricTile key={label} label={label} value={value} icon={Icon} valueClass={cls} />
        ))}
      </div>

      <SectionCard>
        <h2 className="text-sm font-semibold text-foreground mb-2">Calculation Basis</h2>
        <p className="text-sm text-muted-foreground leading-relaxed">{data.calculation_basis}</p>
        <div className="mt-3 flex gap-4 text-xs text-muted-foreground">
          <span>Confidence: {fmtConfidence(data.confidence)}</span>
          <span>Source: {data.source}</span>
          <span>Computed: {new Date(data.computed_at).toLocaleString()}</span>
        </div>
      </SectionCard>
    </div>
  );
}

function RecommendationsTab({ initialData }: { initialData?: ExecutiveRecommendations }) {
  const [loading, setLoading] = useState(!initialData);
  const [data, setData] = useState<ExecutiveRecommendations | null>(initialData ?? null);
  const [error, setError] = useState<string | null>(null);
  const hasInitialRef = useRef(Boolean(initialData));

  useEffect(() => {
    if (hasInitialRef.current) return;
    let cancelled = false;
    getExecutiveRecommendations().then((r) => {
      if (cancelled) return;
      setLoading(false);
      if (!r.ok) { setError(r.error); return; }
      setData(r.data);
    });
    return () => { cancelled = true; };
  }, []);

  if (loading) return <LoadingRow />;
  if (error) return <ErrorRow msg={error} />;
  if (!data) return null;

  return (
    <div className="flex flex-col gap-6">
      <div className="flex items-center gap-4 text-xs text-muted-foreground">
        <span>Total: {data.total}</span>
        <span className="text-red-400">Critical: {data.critical_count}</span>
        <span>Source: {data.source}</span>
        <span>Computed: {new Date(data.computed_at).toLocaleString()}</span>
      </div>

      {data.recommendations.length === 0 ? (
        <p className="text-sm text-muted-foreground">No recommendations at this time.</p>
      ) : (
        <div className="flex flex-col gap-4">
          {data.recommendations.map((rec, i) => (
            <SectionCard key={rec.recommendation_id}>
              <div className="flex items-start gap-3">
                <span className="text-lg font-semibold text-muted-foreground w-7 shrink-0">{i + 1}.</span>
                <div className="flex flex-col gap-2 flex-1">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="text-sm font-semibold text-foreground">{rec.title}</span>
                    <span className={`text-xs px-1.5 py-0.5 rounded capitalize ${severityBadge(rec.priority)}`}>{rec.priority}</span>
                  </div>
                  <p className="text-xs text-muted-foreground leading-relaxed">{rec.rationale}</p>
                  <div className="grid grid-cols-2 gap-x-6 gap-y-1 text-xs mt-1 sm:grid-cols-4">
                    <div>
                      <span className="text-muted-foreground">Impact: </span>
                      <span className="text-foreground">{rec.impact}</span>
                    </div>
                    <div>
                      <span className="text-muted-foreground">Effort: </span>
                      <span className="text-foreground">{rec.estimated_effort}</span>
                    </div>
                    <div>
                      <span className="text-muted-foreground">Value: </span>
                      <span className="text-foreground">{rec.business_value}</span>
                    </div>
                    <div>
                      <span className="text-muted-foreground">Evidence: </span>
                      <span className="text-foreground">{rec.supporting_evidence_count}</span>
                    </div>
                  </div>
                  <div className="flex gap-3 text-xs text-muted-foreground">
                    <span>Confidence: {fmtConfidence(rec.confidence)}</span>
                    {rec.owner && <span>Owner: {rec.owner}</span>}
                    {rec.framework_references.length > 0 && (
                      <span>Frameworks: {rec.framework_references.join(', ')}</span>
                    )}
                  </div>
                </div>
              </div>
            </SectionCard>
          ))}
        </div>
      )}
    </div>
  );
}

function ForecastTab({ initialData }: { initialData?: ExecutiveForecast }) {
  const [loading, setLoading] = useState(!initialData);
  const [data, setData] = useState<ExecutiveForecast | null>(initialData ?? null);
  const [error, setError] = useState<string | null>(null);
  const hasInitialRef = useRef(Boolean(initialData));

  useEffect(() => {
    if (hasInitialRef.current) return;
    let cancelled = false;
    getExecutiveForecast().then((r) => {
      if (cancelled) return;
      setLoading(false);
      if (!r.ok) { setError(r.error); return; }
      setData(r.data);
    });
    return () => { cancelled = true; };
  }, []);

  if (loading) return <LoadingRow />;
  if (error) return <ErrorRow msg={error} />;
  if (!data) return null;

  return (
    <div className="flex flex-col gap-6">
      <div className="flex items-center gap-2 px-3 py-2 rounded-lg bg-blue-500/5 border border-blue-500/20">
        <Brain className="h-4 w-4 text-blue-400 shrink-0" aria-hidden="true" />
        <span className="text-xs text-blue-400">
          Evidence-backed forecast — not AI-generated prediction. All projections derived from authoritative governance data.
        </span>
      </div>

      {data.disclaimer && (
        <p className="text-xs text-muted-foreground italic">{data.disclaimer}</p>
      )}

      <div className="grid gap-4 sm:grid-cols-2">
        {data.forecasts.map((f) => {
          const delta = f.projected_value - f.current_value;
          return (
            <SectionCard key={`${f.domain}-${f.label}`}>
              <div className="flex items-center gap-2 mb-3">
                <span className={`text-xs px-1.5 py-0.5 rounded capitalize ${trendColor(f.trend)} bg-surface border border-border`}>{f.domain}</span>
                <h3 className="text-sm font-semibold text-foreground">{f.label}</h3>
                <span className={`ml-auto text-xs ${trendColor(f.trend)}`}>
                  {trendArrow(f.trend)} {f.trend}
                </span>
              </div>
              <div className="flex gap-6 mb-3">
                <div>
                  <div className="text-xs text-muted-foreground">Current</div>
                  <div className={`text-xl font-semibold ${scoreColor(f.current_value)}`}>{f.current_value.toFixed(0)}</div>
                </div>
                <div>
                  <div className="text-xs text-muted-foreground">Projected ({new Date(f.projection_date).toLocaleDateString()})</div>
                  <div className={`text-xl font-semibold ${delta > 0 ? 'text-green-400' : delta < 0 ? 'text-red-400' : 'text-foreground'}`}>
                    {f.projected_value.toFixed(0)}
                    <span className="text-xs ml-1 text-muted-foreground">({delta > 0 ? '+' : ''}{delta.toFixed(0)})</span>
                  </div>
                </div>
                <div>
                  <div className="text-xs text-muted-foreground">Confidence</div>
                  <div className="text-xl font-semibold text-foreground">{fmtConfidence(f.confidence)}</div>
                </div>
              </div>
              {f.inputs.length > 0 && (
                <div className="mb-2">
                  <div className="text-xs text-muted-foreground mb-1">Inputs:</div>
                  <ul className="list-disc list-inside text-xs text-muted-foreground space-y-0.5">
                    {f.inputs.map((inp) => <li key={inp}>{inp}</li>)}
                  </ul>
                </div>
              )}
              {f.limitations.length > 0 && (
                <div>
                  <div className="text-xs text-muted-foreground mb-1">Limitations:</div>
                  <ul className="list-disc list-inside text-xs text-muted-foreground space-y-0.5">
                    {f.limitations.map((lim) => <li key={lim}>{lim}</li>)}
                  </ul>
                </div>
              )}
              <div className="mt-2 text-xs text-muted-foreground">Evidence: {f.evidence_count} items</div>
            </SectionCard>
          );
        })}
      </div>

      <div className="text-xs text-muted-foreground">Source: {data.source} · Window: {data.forecast_window_days}d · Computed: {new Date(data.computed_at).toLocaleString()}</div>
    </div>
  );
}

function BoardSummaryTab({ initialData }: { initialData?: ExecutiveSummary }) {
  const [loading, setLoading] = useState(!initialData);
  const [data, setData] = useState<ExecutiveSummary | null>(initialData ?? null);
  const [error, setError] = useState<string | null>(null);
  const hasInitialRef = useRef(Boolean(initialData));

  useEffect(() => {
    if (hasInitialRef.current) return;
    let cancelled = false;
    getExecutiveSummary().then((r) => {
      if (cancelled) return;
      setLoading(false);
      if (!r.ok) { setError(r.error); return; }
      setData(r.data);
    });
    return () => { cancelled = true; };
  }, []);

  if (loading) return <LoadingRow />;
  if (error) return <ErrorRow msg={error} />;
  if (!data) return null;

  return (
    <div className="flex flex-col gap-6">
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        <SectionCard>
          <div className="text-xs text-muted-foreground mb-1">Audit Readiness</div>
          <div className={`text-2xl font-semibold ${scoreColor(data.audit_readiness_score)}`}>
            {data.audit_readiness_score}/100
          </div>
          <div className="text-xs text-muted-foreground mt-1">{data.audit_readiness_label}</div>
        </SectionCard>
        <SectionCard>
          <div className="text-xs text-muted-foreground mb-1">Compliance Status</div>
          <div className="text-sm font-semibold text-foreground leading-snug">{data.compliance_status}</div>
        </SectionCard>
        <SectionCard>
          <div className="text-xs text-muted-foreground mb-1">Data Confidence</div>
          <div className="text-2xl font-semibold text-foreground">{fmtConfidence(data.confidence)}</div>
          <div className="text-xs text-muted-foreground mt-1">Source: {data.source}</div>
        </SectionCard>
      </div>

      <SectionCard>
        <h2 className="text-sm font-semibold text-foreground mb-3">Board Narrative</h2>
        <p className="text-sm text-muted-foreground leading-relaxed">{data.board_narrative}</p>
      </SectionCard>

      <div className="grid gap-4 sm:grid-cols-2">
        <SectionCard>
          <div className="flex items-center gap-2 mb-3">
            <AlertTriangle className="h-4 w-4 text-red-400" aria-hidden="true" />
            <h3 className="text-sm font-semibold text-foreground">Major Risks</h3>
          </div>
          {data.major_risks.length === 0 ? (
            <p className="text-xs text-muted-foreground">None reported.</p>
          ) : (
            <ul className="space-y-1">
              {data.major_risks.map((r) => (
                <li key={r} className="text-xs text-muted-foreground flex items-start gap-1.5">
                  <span className="text-red-400 mt-0.5">•</span> {r}
                </li>
              ))}
            </ul>
          )}
        </SectionCard>

        <SectionCard>
          <div className="flex items-center gap-2 mb-3">
            <TrendingUp className="h-4 w-4 text-green-400" aria-hidden="true" />
            <h3 className="text-sm font-semibold text-foreground">Major Improvements</h3>
          </div>
          {data.major_improvements.length === 0 ? (
            <p className="text-xs text-muted-foreground">None reported.</p>
          ) : (
            <ul className="space-y-1">
              {data.major_improvements.map((imp) => (
                <li key={imp} className="text-xs text-muted-foreground flex items-start gap-1.5">
                  <span className="text-green-400 mt-0.5">•</span> {imp}
                </li>
              ))}
            </ul>
          )}
        </SectionCard>

        <SectionCard>
          <div className="flex items-center gap-2 mb-3">
            <Target className="h-4 w-4 text-blue-400" aria-hidden="true" />
            <h3 className="text-sm font-semibold text-foreground">Strategic Recommendations</h3>
          </div>
          {data.strategic_recommendations.length === 0 ? (
            <p className="text-xs text-muted-foreground">None reported.</p>
          ) : (
            <ol className="space-y-1 list-decimal list-inside">
              {data.strategic_recommendations.map((rec) => (
                <li key={rec} className="text-xs text-muted-foreground">{rec}</li>
              ))}
            </ol>
          )}
        </SectionCard>

        <SectionCard>
          <div className="flex items-center gap-2 mb-3">
            <Clock className="h-4 w-4 text-yellow-400" aria-hidden="true" />
            <h3 className="text-sm font-semibold text-foreground">Upcoming Deadlines</h3>
          </div>
          {data.upcoming_deadlines.length === 0 ? (
            <p className="text-xs text-muted-foreground">No upcoming deadlines.</p>
          ) : (
            <div className="flex flex-col gap-2">
              {data.upcoming_deadlines.map((dl) => (
                <div key={dl.label} className="flex items-center justify-between text-xs">
                  <span className="text-muted-foreground">{dl.label}</span>
                  <div className="flex items-center gap-2">
                    <span className="text-foreground">{new Date(dl.due_date).toLocaleDateString()}</span>
                    <span className={`px-1.5 py-0.5 rounded capitalize ${dl.urgency === 'critical' ? severityBadge('critical') : dl.urgency === 'high' ? severityBadge('high') : 'bg-surface border border-border text-muted-foreground'}`}>
                      {dl.urgency}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </SectionCard>
      </div>

      <div className="text-xs text-muted-foreground">Computed: {new Date(data.computed_at).toLocaleString()}</div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main page
// ---------------------------------------------------------------------------

export default function ExecutivePage() {
  const [activeTab, setActiveTab] = useState<TabId>('overview');
  const [workspaceLoading, setWorkspaceLoading] = useState(true);
  const [workspace, setWorkspace] = useState<ExecutiveWorkspace | null>(null);

  useEffect(() => {
    let cancelled = false;
    getExecutiveWorkspace().then((r) => {
      if (cancelled) return;
      setWorkspaceLoading(false);
      if (r.ok) setWorkspace(r.data);
      // On failure workspace stays null; tabs self-fetch via individual endpoints
    });
    return () => { cancelled = true; };
  }, []);

  const sections = workspace?.sections;

  return (
    <div className="flex flex-col">
      <TopBar
        title="Executive Intelligence"
        subtitle="Strategic Governance Command Center"
      />

      <div className="flex flex-col gap-0 p-6">
        {/* Tab navigation */}
        <div className="flex gap-1 border-b border-border mb-6 overflow-x-auto">
          {TABS.map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`px-4 py-2 text-xs font-medium whitespace-nowrap border-b-2 transition-colors ${
                activeTab === tab.id
                  ? 'border-primary text-foreground'
                  : 'border-transparent text-muted-foreground hover:text-foreground'
              }`}
            >
              {tab.label}
            </button>
          ))}
        </div>

        {/* Tab content */}
        {workspaceLoading && <LoadingRow />}
        {!workspaceLoading && (
          <div aria-label="executive-tab-content">
            {activeTab === 'overview' && <OverviewTab initialData={sections?.overview} />}
            {activeTab === 'risk' && <RiskTab initialData={sections?.risk} />}
            {activeTab === 'compliance' && <ComplianceTab initialData={sections?.compliance} />}
            {activeTab === 'trends' && <TrendsTab initialData={sections?.trends} />}
            {activeTab === 'business' && <BusinessTab initialData={sections?.business} />}
            {activeTab === 'recommendations' && <RecommendationsTab initialData={sections?.recommendations} />}
            {activeTab === 'forecast' && <ForecastTab initialData={sections?.forecast} />}
            {activeTab === 'board' && <BoardSummaryTab initialData={sections?.summary} />}
          </div>
        )}
      </div>
    </div>
  );
}
