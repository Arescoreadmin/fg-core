/**
 * Executive Intelligence Center API client — PR 18.6.7
 *
 * All requests proxy through /api/core → admin-gateway → fg-core.
 * BFF adds X-API-Key and X-Tenant-ID server-side; no secrets touch the browser.
 * All functions return SafeResult<T> — never throw to callers.
 *
 * Security invariants:
 *  - No tenant_id from browser URL/body — resolved server-side by BFF.
 *  - No fabricated metrics — all values from authoritative API.
 *  - 403 = no tenant context; UI renders safe state.
 *  - 404 = resource not found; UI must not disclose.
 */

const BFF = '/api/core';

// ---------------------------------------------------------------------------
// SafeResult — never throws to callers
// ---------------------------------------------------------------------------

export type SafeResult<T> =
  | { ok: true; data: T }
  | { ok: false; error: string; status?: number };

async function safeGet<T>(url: string): Promise<SafeResult<T>> {
  try {
    const resp = await fetch(url, { cache: 'no-store' });
    if (!resp.ok) {
      let detail = `HTTP ${resp.status}`;
      try {
        const body = await resp.json();
        if (body?.detail?.message) detail = body.detail.message;
        else if (typeof body?.detail === 'string') detail = body.detail;
      } catch {
        /* ignore parse errors */
      }
      return { ok: false, error: detail, status: resp.status };
    }
    const data: T = await resp.json();
    return { ok: true, data };
  } catch {
    return { ok: false, error: 'Network error — core unreachable' };
  }
}

// ---------------------------------------------------------------------------
// Response types
// ---------------------------------------------------------------------------

export interface ExecutiveOverview {
  governance_health_score: number;       // 0–100
  compliance_score: number;              // 0–100
  risk_score: number;                    // 0–100 (higher = more risk)
  identity_health_score: number;         // 0–100
  evidence_freshness_score: number;      // 0–100
  control_coverage_pct: number;          // 0–100
  open_findings_count: number;
  critical_findings_count: number;
  high_findings_count: number;
  automation_coverage_pct: number;       // 0–100
  executive_summary: string;
  computed_at: string;
  data_window_days: number;
  confidence: number;                    // 0–1
  source: string;
}

export interface FrameworkPosture {
  framework_id: string;
  framework_name: string;
  coverage_pct: number;
  gap_count: number;
  risk_classification: string;           // critical | high | medium | low
  confidence: number;                    // 0–1
  trend: 'improving' | 'stable' | 'degrading';
  last_assessed_at: string | null;
}

export interface ExecutivePosture {
  frameworks: FrameworkPosture[];
  overall_posture: string;               // strong | adequate | weak | critical
  posture_trend: 'improving' | 'stable' | 'degrading';
  computed_at: string;
  evidence_count: number;
}

export interface RiskItem {
  risk_id: string;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  likelihood: 'very_high' | 'high' | 'medium' | 'low' | 'very_low';
  category: string;
  description: string;
  detected_at: string;
  owner: string | null;
  remediation_target: string | null;
  evidence_count: number;
}

export interface ExecutiveRisk {
  top_risks: RiskItem[];
  open_findings_by_severity: Record<string, number>;
  risk_score: number;                    // 0–100
  risk_trend: 'improving' | 'stable' | 'degrading';
  heatmap: Array<{
    severity: string;
    likelihood: string;
    count: number;
  }>;
  computed_at: string;
  source: string;
}

export interface FrameworkCompliance {
  framework_id: string;
  framework_name: string;
  coverage_pct: number;
  gap_count: number;
  confidence: number;
  trend: 'improving' | 'stable' | 'degrading';
  last_assessed_at: string | null;
}

export interface ExecutiveCompliance {
  frameworks: FrameworkCompliance[];
  overall_compliance_score: number;      // 0–100
  frameworks_at_risk: number;
  total_gaps: number;
  computed_at: string;
  source: string;
  confidence: number;
}

export interface ExecutiveBusiness {
  cost_of_risk_estimate_usd: number | null;
  regulatory_exposure_usd: number | null;
  business_continuity_score: number;    // 0–100
  insurance_readiness_score: number;    // 0–100
  audit_readiness_score: number;        // 0–100
  expected_remediation_cost_usd: number | null;
  revenue_at_risk_pct: number | null;
  computed_at: string;
  source: string;
  confidence: number;
  calculation_basis: string;
}

export interface TrendDataPoint {
  date: string;
  value: number;
}

export interface ExecutiveTrends {
  window: '30d' | '90d' | '180d' | '365d';
  governance_trend: TrendDataPoint[];
  compliance_trend: TrendDataPoint[];
  risk_trend: TrendDataPoint[];
  identity_trend: TrendDataPoint[];
  evidence_freshness_trend: TrendDataPoint[];
  computed_at: string;
  source: string;
}

export interface Recommendation {
  recommendation_id: string;
  priority: 'critical' | 'high' | 'medium' | 'low';
  title: string;
  rationale: string;
  impact: string;
  estimated_effort: string;             // e.g. '1-2 weeks'
  business_value: string;
  supporting_evidence_count: number;
  owner: string | null;
  confidence: number;                   // 0–1
  framework_references: string[];
}

export interface ExecutiveRecommendations {
  recommendations: Recommendation[];
  total: number;
  critical_count: number;
  computed_at: string;
  source: string;
}

export interface ForecastItem {
  domain: string;                       // risk | compliance | identity | governance
  label: string;
  current_value: number;
  projected_value: number;
  projection_date: string;
  confidence: number;                   // 0–1
  inputs: string[];
  limitations: string[];
  evidence_count: number;
  trend: 'improving' | 'stable' | 'degrading';
}

export interface ExecutiveForecast {
  forecasts: ForecastItem[];
  forecast_window_days: number;
  computed_at: string;
  source: string;
  disclaimer: string;
}

export interface ExecutivePriorities {
  critical_actions: Array<{
    action_id: string;
    title: string;
    due_date: string | null;
    owner: string | null;
    urgency: string;
    estimated_effort: string;
  }>;
  upcoming_deadlines: Array<{
    deadline_id: string;
    label: string;
    due_date: string;
    framework: string | null;
    status: string;
  }>;
  computed_at: string;
  source: string;
}

export interface ExecutiveSummary {
  major_risks: string[];
  major_improvements: string[];
  compliance_status: string;
  strategic_recommendations: string[];
  upcoming_deadlines: Array<{
    label: string;
    due_date: string;
    urgency: string;
  }>;
  audit_readiness_score: number;        // 0–100
  audit_readiness_label: string;
  board_narrative: string;
  computed_at: string;
  source: string;
  confidence: number;
}

// ---------------------------------------------------------------------------
// API functions
// ---------------------------------------------------------------------------

export async function getExecutiveOverview(): Promise<SafeResult<ExecutiveOverview>> {
  return safeGet<ExecutiveOverview>(`${BFF}/api/executive/overview`);
}

export async function getExecutivePosture(): Promise<SafeResult<ExecutivePosture>> {
  return safeGet<ExecutivePosture>(`${BFF}/api/executive/posture`);
}

export async function getExecutiveRisk(): Promise<SafeResult<ExecutiveRisk>> {
  return safeGet<ExecutiveRisk>(`${BFF}/api/executive/risk`);
}

export async function getExecutiveCompliance(): Promise<SafeResult<ExecutiveCompliance>> {
  return safeGet<ExecutiveCompliance>(`${BFF}/api/executive/compliance`);
}

export async function getExecutiveBusiness(): Promise<SafeResult<ExecutiveBusiness>> {
  return safeGet<ExecutiveBusiness>(`${BFF}/api/executive/business`);
}

export async function getExecutiveTrends(
  window: '30d' | '90d' | '180d' | '365d' = '90d',
): Promise<SafeResult<ExecutiveTrends>> {
  return safeGet<ExecutiveTrends>(`${BFF}/api/executive/trends?window=${window}`);
}

export async function getExecutiveRecommendations(): Promise<SafeResult<ExecutiveRecommendations>> {
  return safeGet<ExecutiveRecommendations>(`${BFF}/api/executive/recommendations`);
}

export async function getExecutiveForecast(): Promise<SafeResult<ExecutiveForecast>> {
  return safeGet<ExecutiveForecast>(`${BFF}/api/executive/forecast`);
}

export async function getExecutivePriorities(): Promise<SafeResult<ExecutivePriorities>> {
  return safeGet<ExecutivePriorities>(`${BFF}/api/executive/priorities`);
}

export async function getExecutiveSummary(): Promise<SafeResult<ExecutiveSummary>> {
  return safeGet<ExecutiveSummary>(`${BFF}/api/executive/summary`);
}

// ---------------------------------------------------------------------------
// Workspace aggregate
// ---------------------------------------------------------------------------

export interface ExecutiveWorkspace {
  tenant_id: string;
  generated_at: string;
  snapshot_version: string;
  source: string;
  calculation: string;
  evidence_summary: {
    findings_total: number;
    open_findings: number;
    decisions_total: number;
    audit_events: number;
    requirements_total: number;
  };
  sections: {
    overview: ExecutiveOverview;
    posture: ExecutivePosture;
    risk: ExecutiveRisk;
    compliance: ExecutiveCompliance;
    business: ExecutiveBusiness;
    trends: ExecutiveTrends;
    recommendations: ExecutiveRecommendations;
    forecast: ExecutiveForecast;
    priorities: ExecutivePriorities;
    summary: ExecutiveSummary;
  };
}

export async function getExecutiveWorkspace(): Promise<SafeResult<ExecutiveWorkspace>> {
  return safeGet<ExecutiveWorkspace>(`${BFF}/api/executive/workspace`);
}
