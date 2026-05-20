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
  | 'scheduled'
  | 'pre_visit'
  | 'in_progress'
  | 'evidence_collected'
  | 'report_generation'
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

export type EvidenceEntityType = 'scan_result' | 'document_analysis' | 'field_observation' | 'attestation';

// Allowed transitions — mirrors backend VALID_ENGAGEMENT_TRANSITIONS
export const VALID_TRANSITIONS: Record<EngagementStatus, EngagementStatus[]> = {
  scheduled: ['pre_visit', 'cancelled'],
  pre_visit: ['in_progress', 'cancelled'],
  in_progress: ['evidence_collected', 'cancelled'],
  evidence_collected: ['report_generation', 'cancelled'],
  report_generation: ['delivered', 'cancelled'],
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

  // Audit events (read-only — append-only server-side)
  listAuditEvents(engagementId: string): Promise<AuditEvent[]> {
    return request(`/engagements/${engagementId}/audit-events`);
  },
};
