/**
 * Readiness API client — Enterprise Readiness Dashboard (PR 91)
 *
 * All requests proxy through /api/core → admin-gateway → fg-core.
 * The BFF adds X-API-Key and X-Tenant-ID server-side; no secrets ever touch
 * the browser. All functions return SafeResult<T> — never throw to callers.
 *
 * Security invariants:
 *  - No tenant_id from browser URL/body — resolved server-side by BFF.
 *  - No raw evidence bodies, prompts, vectors, provider payloads, or secrets.
 *  - No client-side governance scoring — all values come from authoritative API.
 *  - 403 = no tenant context (platform key); UI must render safe state.
 *  - 404 = resource not found or cross-tenant isolation; UI must not disclose.
 */

import { resolveConsoleUrl } from '@/lib/consoleUrl';

const BFF = '/api/core';

// ---------------------------------------------------------------------------
// SafeResult — never throws to callers
// ---------------------------------------------------------------------------

export type SafeResult<T> =
  | { ok: true; data: T }
  | { ok: false; error: string; status?: number };

async function safeGet<T>(url: string): Promise<SafeResult<T>> {
  try {
    const resp = await fetch(await resolveConsoleUrl(url), { cache: 'no-store' });
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
// Framework types
// ---------------------------------------------------------------------------

export interface Framework {
  framework_id: string;
  framework_name: string;
  framework_slug: string;
  framework_version: string;
  framework_status: string; // draft | active | deprecated | retired
  created_at: string;
  updated_at: string;
}

// All list endpoints return bare JSON arrays (list[...] in FastAPI),
// not paginated wrappers — see api/readiness_manager.py.
export type FrameworkListResponse = Framework[];

// ---------------------------------------------------------------------------
// Assessment types
// ---------------------------------------------------------------------------

export interface Assessment {
  assessment_id: string;
  framework_id: string;
  framework_version_tag: string;
  assessment_status: string; // draft | collecting | partially_evaluated | finalized | stale | deprecated | superseded | invalidated
  assessment_name: string | null;
  assessment_description: string | null;
  scoring_contract_id: string | null;
  snapshot_version: number;
  created_by: string;
  created_at: string;
  updated_at: string;
  activated_at: string | null;
  finalized_at: string | null;
  archived_at: string | null;
}

export type AssessmentListResponse = Assessment[];

// ---------------------------------------------------------------------------
// Score output types (mirrors ScoreOutputResponse from api/readiness_manager.py)
// ---------------------------------------------------------------------------

export interface DomainScore {
  domain_id: string;
  domain_name: string;
  raw_score: number;
  normalized_score: number;
  weight: number;
  completion_percentage: number;
  missing_control_count: number;
  incomplete_control_count: number;
  failed_control_count: number;
  risk_classification: string; // critical | high | medium | low | unknown
  threshold_failed: boolean;
}

export interface ControlScore {
  control_id: string;
  control_identifier: string;
  domain_id: string;
  outcome: string;
  raw_score: number;
  weight: number;
  is_evaluated: boolean;
  is_applicable: boolean;
  evidence_count: number;
}

export interface ThresholdFailure {
  threshold_type: string;
  threshold_name: string;
  required_value: number;
  actual_value: number;
  message: string;
}

export interface RemediationFactor {
  factor_type: string;
  description: string;
  severity: string;
}

export interface ScoreOutput {
  assessment_id: string;
  framework_id: string;
  framework_version_tag: string;
  overall_score: number; // 0–100
  normalized_score: number; // 0–1
  domain_scores: Record<string, DomainScore>;
  control_scores: Record<string, ControlScore>;
  maturity_tier: string | null;
  maturity_tier_id: string | null;
  risk_classification: string; // critical | high | medium | low | unknown
  remediation_priority: string;
  remediation_factors: RemediationFactor[];
  missing_controls: string[];
  incomplete_controls: string[];
  failed_controls: string[];
  not_applicable_controls: string[];
  threshold_failures: ThresholdFailure[];
  scoring_warnings: string[];
  completion_state: string;
  completion_percentage: number;
  is_complete: boolean;
  computed_at: string;
  score_version: string;
  scoring_contract_id: string | null;
  scoring_contract_version: string | null;
}

// ---------------------------------------------------------------------------
// Gap analysis types (mirrors GapAnalysisResultResponse)
// ---------------------------------------------------------------------------

export interface ReadinessGap {
  gap_id: string;
  gap_classification: string; // missing_evidence | stale_evidence | failed_control | threshold_failure | maturity_gap
  gap_severity: string; // critical | high | medium | low
  framework_id: string;
  framework_version: string;
  gap_rationale: string;
  detected_at: string;
  is_blocker: boolean;
  is_maturity_blocker: boolean;
  affected_control_ids: string[];
  affected_framework_ids: string[];
  evidence_ids: string[];
  control_id: string | null;
  domain_id: string | null;
}

export interface ReadinessBlocker {
  blocker_id: string;
  gap_id: string;
  blocker_rationale: string;
  severity: string;
  affected_framework_ids: string[];
  affected_control_ids: string[];
}

export interface MaturityBlocker {
  blocker_id: string;
  gap_id: string;
  maturity_tier_id: string;
  blocker_rationale: string;
  affected_control_ids: string[];
}

export interface DependencyChain {
  chain_id: string;
  ordered_gap_ids: string[];
  has_cycle: boolean;
  cycle_gap_ids: string[];
}

export interface RemediationRecommendation {
  recommendation_id: string;
  gap_id: string;
  remediation_classification: string;
  remediation_rationale: string;
  affected_control_ids: string[];
  affected_domain_ids: string[];
  affected_framework_ids: string[];
  estimated_readiness_impact: number;
  maturity_implications: string;
  governance_rationale: string;
  dependency_ids: string[];
  blocker_ids: string[];
  compensating_control_ids: string[];
}

export interface PolicyException {
  exception_id: string;
  exception_type: string;
  exception_authority: string;
  approval_rationale: string;
  affected_control_ids: string[];
  affected_framework_ids: string[];
  approved_at: string;
  expires_at: string | null;
}

export interface CompensatingControl {
  compensating_id: string;
  gap_id: string;
  mitigation_rationale: string;
  framework_applicability: string[];
  approved_by: string;
  approved_at: string;
}

export interface GovernanceOverride {
  override_id: string;
  gap_id: string;
  override_type: string;
  original_value: string;
  overridden_value: string;
  override_authority: string;
  override_rationale: string;
  approved_at: string;
}

export interface EvidenceFreshnessRecord {
  freshness_id: string;
  evidence_id: string;
  control_id: string | null;
  framework_id: string;
  framework_version: string;
  submitted_at: string;
  freshness_window_days: number;
  is_stale: boolean;
  staleness_days: number | null;
  evaluated_at: string;
}

export interface GapReplayContract {
  contract_id: string;
  result_id: string;
  framework_version: string;
  analysis_version: string;
  scoring_contract_version: string | null;
  maturity_model_version: string | null;
  mapping_version: string | null;
  evidence_snapshot_version: string | null;
}

export interface GapAnalysisResult {
  result_id: string;
  assessment_id: string | null;
  framework_id: string;
  framework_version: string;
  analysis_version: string;
  analyzed_at: string;
  gaps: ReadinessGap[];
  readiness_blockers: ReadinessBlocker[];
  maturity_blockers: MaturityBlocker[];
  dependency_chains: DependencyChain[];
  remediation_recommendations: RemediationRecommendation[];
  impact_estimates: unknown[];
  policy_exceptions: PolicyException[];
  compensating_controls: CompensatingControl[];
  governance_overrides: GovernanceOverride[];
  evidence_freshness_records: EvidenceFreshnessRecord[];
  replay_contract: GapReplayContract;
  scoring_contract_version: string | null;
  maturity_model_version: string | null;
  mapping_version: string | null;
  evidence_snapshot_version: string | null;
}

// ---------------------------------------------------------------------------
// API functions
// ---------------------------------------------------------------------------

export async function listFrameworks(
  limit = 50,
  offset = 0,
): Promise<SafeResult<Framework[]>> {
  return safeGet<Framework[]>(
    `${BFF}/control-plane/readiness/frameworks?limit=${limit}&offset=${offset}`,
  );
}

export async function getFramework(frameworkId: string): Promise<SafeResult<Framework>> {
  return safeGet<Framework>(`${BFF}/control-plane/readiness/frameworks/${frameworkId}`);
}

export async function listAssessments(
  frameworkId?: string,
  limit = 50,
  offset = 0,
): Promise<SafeResult<Assessment[]>> {
  const params = new URLSearchParams({ limit: String(limit), offset: String(offset) });
  if (frameworkId) params.set('framework_id', frameworkId);
  return safeGet<Assessment[]>(
    `${BFF}/control-plane/readiness/assessments?${params}`,
  );
}

export async function getAssessment(assessmentId: string): Promise<SafeResult<Assessment>> {
  return safeGet<Assessment>(
    `${BFF}/control-plane/readiness/assessments/${assessmentId}`,
  );
}

export async function getScore(assessmentId: string): Promise<SafeResult<ScoreOutput>> {
  return safeGet<ScoreOutput>(
    `${BFF}/control-plane/readiness/assessments/${assessmentId}/score`,
  );
}

export async function getGapAnalysis(
  assessmentId: string,
): Promise<SafeResult<GapAnalysisResult>> {
  return safeGet<GapAnalysisResult>(
    `${BFF}/control-plane/readiness/assessments/${assessmentId}/gap-analysis`,
  );
}

export async function listDomains(
  frameworkId: string,
  limit = 200,
  offset = 0,
): Promise<SafeResult<unknown[]>> {
  return safeGet(
    `${BFF}/control-plane/readiness/frameworks/${frameworkId}/domains?limit=${limit}&offset=${offset}`,
  );
}

// ---------------------------------------------------------------------------
// Future seams — type stubs only, no API routes wired yet.
// These define the shape of future surfaces without implementation.
// ---------------------------------------------------------------------------

// Gap 1 — Temporal trend visibility
// Historical posture tracking: score movement, remediation progress, regression alerts.
// Wire to a future GET /control-plane/readiness/assessments/{id}/score-history endpoint.
// DOM seam: aria-label="posture-trend-panel" reserved in readiness page.
export interface ScoreHistoryEntry {
  computed_at: string;
  overall_score: number;
  normalized_score: number;
  risk_classification: string;
  completion_percentage: number;
  maturity_tier: string | null;
}
// export async function getScoreHistory(assessmentId: string): Promise<SafeResult<ScoreHistoryEntry[]>>

// Gap 2 — "Why This Matters" operational impact layer
// Structured rationale for operators, executives, and audit teams — not AI prose.
// Wire to future governance consequence fields on the gap analysis response.
export interface OperationalImpact {
  impact_id: string;
  gap_id: string;
  impact_domain: string; // e.g. 'availability' | 'confidentiality' | 'regulatory'
  consequence: string;
  regulatory_references: string[];
  audit_relevance: string;
}
// Surfaced as: GapAnalysisResult.operational_impacts (future field on existing type)

// Gap 3 — Cross-framework comparison and crosswalk visualization
// assess-once → map-many: overlapping controls, inherited mappings, framework conflicts.
// Wire to future GET /control-plane/readiness/crosswalk?framework_ids=... endpoint.
export interface CrosswalkControlMapping {
  source_framework_id: string;
  target_framework_id: string;
  source_control_id: string;
  target_control_id: string;
  mapping_type: string; // 'equivalent' | 'partial' | 'parent' | 'child'
  inherited: boolean;
}
export interface FrameworkCrosswalk {
  crosswalk_id: string;
  framework_ids: string[];
  mappings: CrosswalkControlMapping[];
  conflict_control_ids: string[];
  coverage_percentage: number;
}
// export async function getFrameworkCrosswalk(frameworkIds: string[]): Promise<SafeResult<FrameworkCrosswalk>>

// Gap 4 — Reviewer workflow context
// Signoff state, approval lineage, governance acknowledgment for regulated industries.
// Wire to future GET /control-plane/readiness/assessments/{id}/reviewer-context endpoint.
// DOM seam: aria-label="reviewer-workflow-panel" reserved in SnapshotContext / readiness page.
export interface ReviewerAssignment {
  reviewer_id: string;
  reviewer_role: string;
  assigned_at: string;
  signed_off: boolean;
  signed_off_at: string | null;
  signoff_notes: string | null;
}
export interface ReviewerContext {
  assessment_id: string;
  workflow_state: string; // 'pending_review' | 'in_review' | 'approved' | 'rejected' | 'escalated'
  reviewers: ReviewerAssignment[];
  approval_lineage: string[];
  governance_acknowledged: boolean;
  acknowledged_at: string | null;
}
// export async function getReviewerContext(assessmentId: string): Promise<SafeResult<ReviewerContext>>

// Gap 5 — Runtime governance correlation
// Connect live runtime drift (retrieval degradation, provenance failures, grounding failures)
// into readiness posture. Wire to existing runtime telemetry endpoints.
export interface RuntimeCorrelationFactor {
  factor_type: string; // 'retrieval_degradation' | 'provenance_failure' | 'grounding_failure' | 'policy_drift'
  severity: string;
  correlated_control_ids: string[];
  event_count: number;
  first_observed: string;
  last_observed: string;
  readiness_impact_estimate: number;
}
export interface RuntimeCorrelationSummary {
  assessment_id: string;
  correlated_at: string;
  factors: RuntimeCorrelationFactor[];
  aggregate_readiness_delta: number;
}
// export async function getRuntimeCorrelation(assessmentId: string): Promise<SafeResult<RuntimeCorrelationSummary>>
