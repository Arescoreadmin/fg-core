/**
 * fieldAssessmentApi.ts
 *
 * Typed API client for the Field Assessment Engagement Substrate.
 * All requests route through the BFF at /api/core/field-assessment/...
 * which injects X-Tenant-ID from CORE_TENANT_ID server-side.
 *
 * Security invariants:
 *  - tenant_id is NEVER sent in request bodies or query params
 *  - raw scan payloads are never stored in frontend state beyond submission
 *  - evidence hashes are displayed but payloads are not echoed to the UI
 */

const BASE = '/api/core/field-assessment';

// ---------------------------------------------------------------------------
// Shared types
// ---------------------------------------------------------------------------

export type EngagementStatus =
  | 'in_progress'
  | 'delivered'
  | 'remediation'
  | 'monitoring'
  | 'closed'
  | 'cancelled';

export type AssessmentType =
  | 'ai_governance'
  | 'cmmc'
  | 'hipaa'
  | 'soc2'
  | 'iso27001'
  | 'comprehensive';

export type ScanSourceType =
  | 'microsoft_graph'
  | 'google_workspace'
  | 'aws'
  | 'azure'
  | 'gcp'
  | 'network_scan'
  | 'endpoint_inventory'
  | 'oauth_inventory';

export type DocumentClassification =
  | 'ai_policy'
  | 'data_governance'
  | 'incident_response'
  | 'vendor_risk'
  | 'access_control'
  | 'training_records'
  | 'audit_reports'
  | 'other';

export type ObservationDomain =
  | 'ai_governance'
  | 'data_security'
  | 'access_management'
  | 'operational_security'
  | 'compliance'
  | 'vendor_management'
  | 'incident_response'
  | 'training';

export type ObservationType = 'gap' | 'strength' | 'concern' | 'finding' | 'note' | 'interview';

export type ObservationSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type FindingSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type FindingStatus = 'open' | 'acknowledged' | 'remediated' | 'accepted_risk' | 'closed';

export type EvidenceEntityType = 'scan_result' | 'document_analysis' | 'field_observation' | 'attestation' | 'questionnaire_response';

// Allowed transitions — mirrors backend VALID_ENGAGEMENT_TRANSITIONS
export const VALID_TRANSITIONS: Record<EngagementStatus, EngagementStatus[]> = {
  in_progress: ['cancelled'],
  delivered: ['remediation', 'monitoring', 'closed'],
  remediation: ['monitoring', 'closed'],
  monitoring: ['remediation', 'closed'],
  closed: [],
  cancelled: [],
};

// ---------------------------------------------------------------------------
// Response shapes
// ---------------------------------------------------------------------------

export interface Engagement {
  id: string;
  client_name: string;
  client_domain: string | null;
  assessor_id: string;
  assessment_type: AssessmentType;
  status: EngagementStatus;
  scheduled_date: string | null;
  client_access_code: string | null;
  engagement_metadata: Record<string, unknown>;
  schema_version: string;
  created_at: string;
  updated_at: string;
}

export interface EngagementListPage {
  items: Engagement[];
  total: number;
  next_cursor: string | null;
}

export interface ScanResultSummary {
  id: string;
  engagement_id: string;
  source_type: ScanSourceType;
  schema_version: string;
  collected_at: string;
  evidence_hash: string;
  object_count: number;
  created_at: string;
}

export interface DocumentAnalysis {
  id: string;
  engagement_id: string;
  document_name: string;
  document_classification: DocumentClassification;
  document_hash: string | null;
  version_label: string | null;
  approved_by: string | null;
  approval_date: string | null;
  freshness_date: string | null;
  analysis_findings: unknown[];
  gaps_identified: unknown[];
  schema_version: string;
  created_at: string;
  updated_at: string;
}

export interface Observation {
  id: string;
  engagement_id: string;
  domain: ObservationDomain;
  observation_type: ObservationType;
  severity: ObservationSeverity;
  title: string;
  description: string;
  interview_role: string | null;
  structured_evidence: Record<string, unknown>;
  linked_finding_ids: string[];
  assessor_id: string;
  schema_version: string;
  created_at: string;
}

export interface Finding {
  id: string;
  engagement_id: string;
  finding_type: string;
  findings_hash: string;
  severity: FindingSeverity;
  status: FindingStatus;
  title: string;
  description: string;
  source_attribution: string;
  confidence_score: number;
  framework_mappings: unknown[];
  nist_ai_rmf_mappings: unknown[];
  evidence_ref_ids: string[];
  remediation_hint: string | null;
  schema_version: string;
  created_at: string;
  updated_at: string;
}

export interface FindingListPage {
  items: Finding[];
  total: number;
  next_cursor: string | null;
}

export interface EvidenceLink {
  id: string;
  engagement_id: string;
  source_entity_type: string;
  source_entity_id: string;
  evidence_entity_type: EvidenceEntityType;
  evidence_entity_id: string;
  link_metadata: Record<string, unknown>;
  schema_version: string;
  created_at: string;
}

export interface EngagementSummary {
  engagement_id: string;
  status: EngagementStatus;
  total_scan_results: number;
  total_document_analyses: number;
  total_observations: number;
  total_findings: number;
  total_evidence_links: number;
  findings_by_severity: Record<string, number>;
  open_findings_count: number;
  critical_findings_count: number;
}

export interface AuditEvent {
  id: string;
  engagement_id: string;
  event_type: string;
  actor: string;
  reason_code: string;
  payload: Record<string, unknown>;
  schema_version: string;
  created_at: string;
}

export interface ConfidenceImpact {
  reason: string;
  delta: number;
  affected_scope: string;
}

export interface ReadinessGate {
  gate_id: string;
  gate_type: string;
  readiness_category: string;
  severity: ObservationSeverity;
  priority: number;
  status: 'passed' | 'warning' | 'blocked' | 'not_applicable';
  title: string;
  explanation: string;
  why_it_matters: string;
  evidence_required: string[];
  evidence_present: string[];
  missing_items: string[];
  related_entity_ids: string[];
  blocks_status_transition: string[];
  recommended_action_id: string | null;
  confidence_impact: ConfidenceImpact | null;
}

export interface ExecutionNextAction {
  action_id: string;
  priority: number;
  title: string;
  instruction: string;
  why_it_matters: string;
  closes_gate_ids: string[];
  required_input_type: string;
  target_ui_section: string;
  expected_evidence: string[];
  safe_for_junior_assessor: boolean;
  severity: ObservationSeverity;
}

export interface EscalationItem {
  escalation_id: string;
  severity: ObservationSeverity;
  reason: string;
  ambiguity_type: string;
  related_entities: string[];
  recommended_reviewer_role: string;
  must_block_progression: boolean;
}

export interface TransitionBlocker {
  target_status: EngagementStatus;
  blocked_by_gate_ids: string[];
  explanation: string;
}

export interface AssetCandidateAction {
  candidate_action_id: string;
  source_type: string;
  source_entity_id: string;
  title: string;
  instruction: string;
  lineage_refs: string[];
  candidate_type: string;
  risk_signal: string;
  confidence: number;
  evidence_refs: string[];
  promotion_state: string;
  target_ui_section: string;
}

export interface ConnectorImportPayload {
  connector_type: 'microsoft_graph';
  connector_run_id: string;
  connector_manifest_hash?: string;
  import_review_status?: 'imported' | 'needs_review' | 'reviewed';
  scan_result: Record<string, unknown>;
}

export interface MsgraphScanInitiatePayload {
  azure_tenant_id: string;
  operator_name?: string;
  operator_org?: string;
  client_org_name?: string;
}

export interface MsgraphScanInitiated {
  run_id: string;
  user_code: string;
  verification_uri: string;
  expires_in: number;
  message: string;
}

export type MsgraphRunStatus =
  | 'pending_auth'
  | 'authenticating'
  | 'scanning'
  | 'importing'
  | 'complete'
  | 'failed'
  | 'timeout';

export interface MsgraphRunStatusResult {
  run_id: string;
  status: MsgraphRunStatus;
  user_code: string | null;
  verification_uri: string | null;
  error: string | null;
  scan_result_id: string | null;
}

export interface ConnectorImportResult {
  engagement_id: string;
  scan_result_id: string;
  connector_type: string;
  connector_run_id: string;
  connector_import_id: string;
  manifest_hash: string;
  integrity_hash: string;
  verification_status: string;
  verification_checks: string[];
  findings_imported: number;
  evidence_links_imported: number;
  asset_candidates_detected: number;
  import_status: string;
  schema_version: string;
}

export interface ContinuityOpportunity {
  opportunity_id: string;
  opportunity_type: string;
  title: string;
  related_entity_ids: string[];
  recommended_follow_up: string;
}

export interface ExecutionState {
  engagement_id: string;
  assessment_type: AssessmentType;
  playbook_id: string;
  playbook_version: string;
  overall_readiness_state: string;
  readiness_score: number;
  completion_ratio: number;
  blocking_gate_count: number;
  warning_gate_count: number;
  completed_gate_count: number;
  gates: ReadinessGate[];
  next_actions: ExecutionNextAction[];
  escalation_items: EscalationItem[];
  transition_blockers: TransitionBlocker[];
  asset_candidate_actions: AssetCandidateAction[];
  continuity_opportunities: ContinuityOpportunity[];
  readiness_categories: Record<string, string>;
  generated_at: string;
  schema_version: string;
}

// ---------------------------------------------------------------------------
// Report types
// ---------------------------------------------------------------------------

export type ReportType = 'full_assessment' | 'executive_summary' | 'findings_register' | 'control_gap';

export interface ReportVersionSummary {
  report_id: string;
  version: number;
  status: string;
  compiled_at: string;
  compiled_by: string | null;
  report_type: string | null;
  qa_approved_by: string | null;
  qa_approved_at: string | null;
}

export interface ReportVersionList {
  items: ReportVersionSummary[];
  limit: number;
  offset: number;
  total: number;
}

export interface ReportDocument {
  report_id: string;
  version: number;
  report_type: string | null;
  compiled_by: string | null;
  manifest_hash: string;
  section_hashes: Record<string, string>;
  signature: string | null;
  generated_at: string;
  schema_version: string;
  report: Record<string, unknown>;
}

export interface ReportVerifyResult {
  valid: boolean;
  manifest_hash: string;
  signature: string | null;
  verified_at: string;
}

export interface GenerateReportPayload {
  report_type: ReportType;
  include_sections?: string[];
  compiled_by?: string;
}

export interface GenerateReportResponse {
  report_id: string;
  version: number;
  status: string;
  compiled_at: string;
}

export interface PlaybookNextAction {
  action_id: string;
  priority: number;
  title: string;
  instruction: string;
  why_it_matters: string;
  closes_gate_ids: string[];
  required_input_type: string;
  target_ui_section: string;
  expected_evidence: string[];
  safe_for_junior_assessor: boolean;
  severity: string;
  blocking: boolean;
  action_type: string;
  deep_link: string | null;
}

export interface PlaybookProgress {
  engagement_id: string;
  current_status: string;
  completion_pct: number;
  blocking_count: number;
  actions: PlaybookNextAction[];
  generated_at: string;
}

export interface AffectedEntitySummary {
  entity_type: string;
  count: number;
  label: string;
}

export interface FindingExplanation {
  finding_id: string;
  finding_type: string;
  severity: string;
  title: string;
  plain_summary: string;
  what_it_means: string;
  affected_entities: AffectedEntitySummary[];
  registry_recommendation: string;
  evidence_count: number;
  source_scan_ids: string[];
  last_seen: string;
  explanation_confidence: number;
  signals_used: string[];
  framework_impact: string[];
  template: string;
  explanation_version: string;
  generated_at: string;
  schema_version: string;
}

// ---------------------------------------------------------------------------
// Request shapes
// ---------------------------------------------------------------------------

export interface CreateEngagementPayload {
  client_name: string;
  client_domain?: string;
  assessment_type: AssessmentType;
  assessor_id: string;
  scheduled_date?: string;
  engagement_metadata?: Record<string, unknown>;
}

export interface TransitionEngagementPayload {
  new_status: EngagementStatus;
  reason: string;
}

export interface IngestScanPayload {
  source_type: ScanSourceType;
  collected_at: string;
  raw_payload: Record<string, unknown>;
  schema_version?: string;
  normalized_payload?: Record<string, unknown>;
  object_count?: number;
  expected_evidence_hash?: string;
}

export interface RegisterDocumentPayload {
  document_name: string;
  document_classification: DocumentClassification;
  document_hash?: string;
  version_label?: string;
  approved_by?: string;
  approval_date?: string;
  freshness_date?: string;
}

export interface CaptureObservationPayload {
  domain: ObservationDomain;
  observation_type: ObservationType;
  severity: ObservationSeverity;
  title: string;
  description: string;
  interview_role?: string;
  structured_evidence?: Record<string, unknown>;
  linked_finding_ids?: string[];
}

export interface CreateEvidenceLinkPayload {
  source_entity_type: string;
  source_entity_id: string;
  evidence_entity_type: EvidenceEntityType;
  evidence_entity_id: string;
  link_metadata?: Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// Questionnaire types
// ---------------------------------------------------------------------------

export type QuestionnaireStatus = 'draft' | 'submitted' | 'finalized';

export type ResponseStatus =
  | 'not_assessed'
  | 'implemented'
  | 'partial'
  | 'not_implemented'
  | 'not_applicable';

export type QuestionnaireCategory = 'GOVERN' | 'MAP' | 'MEASURE' | 'MANAGE';

export interface QuestionnaireResponseItem {
  id: string;
  control_id: string;
  category: QuestionnaireCategory;
  control_name: string;
  response_status: ResponseStatus;
  evidence_text: string | null;
  confidence_score: number | null;
  assessor_id: string | null;
  updated_at: string;
}

export interface Questionnaire {
  id: string;
  engagement_id: string;
  framework: string;
  framework_version: string;
  status: QuestionnaireStatus;
  submitted_at: string | null;
  submitted_by: string | null;
  schema_version: string;
  created_at: string;
  updated_at: string;
  responses: QuestionnaireResponseItem[];
  already_existed: boolean;
}

export interface PatchResponsePayload {
  response_status: ResponseStatus;
  evidence_text?: string | null;
  confidence_score?: number | null;
}

export interface QuestionnaireResponseUpdate {
  id: string;
  control_id: string;
  response_status: ResponseStatus;
  evidence_text: string | null;
  confidence_score: number | null;
  updated_at: string;
}

export interface QuestionnaireCoverage {
  questionnaire_id: string;
  total_controls: number;
  assessed_count: number;
  not_assessed_count: number;
  implemented_count: number;
  partial_count: number;
  not_implemented_count: number;
  not_applicable_count: number;
  coverage_pct: number;
  by_category: Record<string, Record<string, number>>;
}

// ---------------------------------------------------------------------------
// API error
// ---------------------------------------------------------------------------

export class FieldAssessmentApiError extends Error {
  constructor(
    public status: number,
    public code: string,
    message: string,
  ) {
    super(message);
    this.name = 'FieldAssessmentApiError';
  }
}

async function request<T>(
  path: string,
  init?: RequestInit,
): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    ...init,
    headers: {
      'Content-Type': 'application/json',
      ...(init?.headers ?? {}),
    },
    cache: 'no-store',
  });
  if (!res.ok) {
    let code = `HTTP_${res.status}`;
    try {
      const body = await res.json();
      code = body?.detail?.code ?? body?.code ?? code;
    } catch { /* noop */ }
    throw new FieldAssessmentApiError(res.status, code, `Field assessment API error ${res.status}`);
  }
  return res.json() as Promise<T>;
}

async function requestBlob(path: string): Promise<Blob> {
  const res = await fetch(`${BASE}${path}`, { cache: 'no-store' });
  if (!res.ok) {
    let code = `HTTP_${res.status}`;
    try {
      const body = await res.json();
      code = body?.detail?.code ?? body?.code ?? code;
    } catch { /* noop */ }
    throw new FieldAssessmentApiError(res.status, code, `Field assessment API error ${res.status}`);
  }
  return res.blob();
}

// ---------------------------------------------------------------------------
// Engagements
// ---------------------------------------------------------------------------

export const fieldAssessmentApi = {
  listEngagements(params?: { status?: string; limit?: number; cursor?: string }): Promise<EngagementListPage> {
    const q = new URLSearchParams();
    if (params?.status) q.set('status', params.status);
    if (params?.limit) q.set('limit', String(params.limit));
    if (params?.cursor) q.set('cursor', params.cursor);
    const qs = q.toString() ? `?${q}` : '';
    return request(`/engagements${qs}`);
  },

  createEngagement(payload: CreateEngagementPayload): Promise<Engagement> {
    return request('/engagements', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  },

  getEngagement(engagementId: string): Promise<Engagement> {
    return request(`/engagements/${engagementId}`);
  },

  transitionEngagement(engagementId: string, payload: TransitionEngagementPayload): Promise<Engagement> {
    return request(`/engagements/${engagementId}/status`, {
      method: 'PATCH',
      body: JSON.stringify(payload),
    });
  },

  // Scan results
  ingestScan(engagementId: string, payload: IngestScanPayload): Promise<ScanResultSummary> {
    return request(`/engagements/${engagementId}/scan-results`, {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  },

  listScans(engagementId: string): Promise<ScanResultSummary[]> {
    return request(`/engagements/${engagementId}/scan-results`);
  },

  // Document analyses
  registerDocument(engagementId: string, payload: RegisterDocumentPayload): Promise<DocumentAnalysis> {
    return request(`/engagements/${engagementId}/document-analyses`, {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  },

  listDocuments(engagementId: string): Promise<DocumentAnalysis[]> {
    return request(`/engagements/${engagementId}/document-analyses`);
  },

  // Observations (includes interviews)
  captureObservation(engagementId: string, payload: CaptureObservationPayload): Promise<Observation> {
    return request(`/engagements/${engagementId}/observations`, {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  },

  listObservations(engagementId: string, params?: { observation_type?: string }): Promise<Observation[]> {
    const q = new URLSearchParams();
    if (params?.observation_type) q.set('observation_type', params.observation_type);
    const qs = q.toString() ? `?${q}` : '';
    return request(`/engagements/${engagementId}/observations${qs}`);
  },

  // Findings (read-only — normalized server-side)
  listFindings(engagementId: string, params?: { severity?: string; status?: string }): Promise<FindingListPage> {
    const q = new URLSearchParams();
    if (params?.severity) q.set('severity', params.severity);
    if (params?.status) q.set('status', params.status);
    const qs = q.toString() ? `?${q}` : '';
    return request(`/engagements/${engagementId}/findings${qs}`);
  },

  getFinding(engagementId: string, findingId: string): Promise<Finding> {
    return request(`/engagements/${engagementId}/findings/${findingId}`);
  },

  patchFindingRemediation(engagementId: string, findingId: string, hint: string): Promise<{ finding_id: string; remediation_hint: string }> {
    return request(`/engagements/${engagementId}/findings/${findingId}/remediation`, {
      method: 'PATCH',
      body: JSON.stringify({ remediation_hint: hint }),
    });
  },

  // Evidence links
  createEvidenceLink(engagementId: string, payload: CreateEvidenceLinkPayload): Promise<EvidenceLink> {
    return request(`/engagements/${engagementId}/evidence-links`, {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  },

  listEvidenceLinks(engagementId: string): Promise<EvidenceLink[]> {
    return request(`/engagements/${engagementId}/evidence-links`);
  },

  // Summary
  getSummary(engagementId: string): Promise<EngagementSummary> {
    return request(`/engagements/${engagementId}/summary`);
  },

  // Deterministic guided execution state (server-authored readiness)
  getExecutionState(engagementId: string): Promise<ExecutionState> {
    return request(`/engagements/${engagementId}/execution-state`);
  },

  importMicrosoftGraphRun(engagementId: string, payload: ConnectorImportPayload): Promise<ConnectorImportResult> {
    return request(`/engagements/${engagementId}/connector-runs/msgraph/import`, {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  },

  initiateMsgraphScan(engagementId: string, payload: MsgraphScanInitiatePayload): Promise<MsgraphScanInitiated> {
    return request(`/engagements/${engagementId}/connector-runs/msgraph/initiate`, {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  },

  getMsgraphRunStatus(engagementId: string, runId: string): Promise<MsgraphRunStatusResult> {
    return request(`/engagements/${engagementId}/connector-runs/${runId}/status`);
  },

  initiateOauthInventoryScan(engagementId: string, payload: MsgraphScanInitiatePayload): Promise<MsgraphScanInitiated> {
    return request(`/engagements/${engagementId}/connector-runs/oauth-inventory/initiate`, {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  },

  initiateEndpointInventoryScan(engagementId: string, payload: MsgraphScanInitiatePayload): Promise<MsgraphScanInitiated> {
    return request(`/engagements/${engagementId}/connector-runs/endpoint-inventory/initiate`, {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  },

  initiateNetworkScan(engagementId: string, payload: { target_hosts: string[] }): Promise<{ run_id: string; status: string; target_count: number }> {
    return request(`/engagements/${engagementId}/connector-runs/network-scan/initiate`, {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  },

  initiateDnsEmailScan(engagementId: string, payload: { domains: string[]; dkim_selectors?: string[] }): Promise<{ run_id: string; status: string; domain_count: number }> {
    return request(`/engagements/${engagementId}/connector-runs/dns-email/initiate`, {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  },

  initiateWebHeadersScan(engagementId: string, payload: { targets: string[] }): Promise<{ run_id: string; status: string; target_count: number }> {
    return request(`/engagements/${engagementId}/connector-runs/web-headers/initiate`, {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  },

  initiateEntraGovernanceScan(engagementId: string, payload: MsgraphScanInitiatePayload): Promise<MsgraphScanInitiated> {
    return request(`/engagements/${engagementId}/connector-runs/entra-governance/initiate`, {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  },

  initiateSharepointScan(engagementId: string, payload: MsgraphScanInitiatePayload): Promise<MsgraphScanInitiated> {
    return request(`/engagements/${engagementId}/connector-runs/sharepoint/initiate`, {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  },

  initiateOauthRiskScan(engagementId: string, payload: MsgraphScanInitiatePayload): Promise<MsgraphScanInitiated> {
    return request(`/engagements/${engagementId}/connector-runs/oauth-risk/initiate`, {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  },

  // Audit events (read-only — append-only server-side)
  listAuditEvents(engagementId: string): Promise<AuditEvent[]> {
    return request(`/engagements/${engagementId}/audit-events`);
  },

  // Reports — signed, versioned governance deliverables
  generateReport(engagementId: string, payload: GenerateReportPayload): Promise<GenerateReportResponse> {
    return request(`/engagements/${engagementId}/reports`, {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  },

  listReports(engagementId: string, params?: { limit?: number; offset?: number }): Promise<ReportVersionList> {
    const q = new URLSearchParams();
    if (params?.limit != null) q.set('limit', String(params.limit));
    if (params?.offset != null) q.set('offset', String(params.offset));
    const qs = q.toString() ? `?${q}` : '';
    return request(`/engagements/${engagementId}/reports${qs}`);
  },

  getReport(engagementId: string, version: number): Promise<ReportDocument> {
    return request(`/engagements/${engagementId}/reports/${version}`);
  },

  exportReport(engagementId: string, version: number, format: 'json' | 'pdf'): Promise<Blob> {
    return requestBlob(`/engagements/${engagementId}/reports/${version}/export?format=${format}`);
  },

  verifyReport(engagementId: string, version: number): Promise<ReportVerifyResult> {
    return request(`/engagements/${engagementId}/reports/${version}/verify`, {
      method: 'POST',
    });
  },

  qaApproveReport(engagementId: string, reportId: string, reviewerName?: string): Promise<{ report_id: string; qa_approved_by: string; qa_approved_at: string; engagement_status: string; client_access_code: string | null }> {
    return request(`/engagements/${engagementId}/reports/${reportId}/qa-approve`, {
      method: 'POST',
      body: JSON.stringify({ reviewer_name: reviewerName ?? null }),
    });
  },

  getNextActions(engagementId: string): Promise<PlaybookProgress> {
    return request(`/engagements/${engagementId}/next-actions`);
  },

  explainFinding(engagementId: string, findingId: string): Promise<FindingExplanation> {
    return request(`/engagements/${engagementId}/findings/${findingId}/explain`);
  },

  // Questionnaire — NIST AI RMF structured per-control evidence capture
  initQuestionnaire(engagementId: string, framework = 'nist_ai_rmf'): Promise<Questionnaire> {
    return request(`/engagements/${engagementId}/questionnaires`, {
      method: 'POST',
      body: JSON.stringify({ framework }),
    });
  },

  getQuestionnaire(engagementId: string, questionnaireId: string): Promise<Questionnaire> {
    return request(`/engagements/${engagementId}/questionnaires/${questionnaireId}`);
  },

  patchResponse(
    engagementId: string,
    questionnaireId: string,
    controlId: string,
    payload: PatchResponsePayload,
  ): Promise<QuestionnaireResponseUpdate> {
    return request(
      `/engagements/${engagementId}/questionnaires/${questionnaireId}/responses/${controlId}`,
      { method: 'PATCH', body: JSON.stringify(payload) },
    );
  },

  submitQuestionnaire(engagementId: string, questionnaireId: string): Promise<Questionnaire> {
    return request(
      `/engagements/${engagementId}/questionnaires/${questionnaireId}/submit`,
      { method: 'POST' },
    );
  },

  getQuestionnaireCoverage(engagementId: string, questionnaireId: string): Promise<QuestionnaireCoverage> {
    return request(`/engagements/${engagementId}/questionnaires/${questionnaireId}/coverage`);
  },
};
