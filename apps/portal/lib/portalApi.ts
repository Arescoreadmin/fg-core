/**
 * portalApi.ts
 *
 * Typed BFF client for the FrostGate Client Portal.
 * All requests are routed through the portal BFF proxy at /api/core,
 * which injects X-Tenant-ID server-side. The client never sends tenant_id.
 *
 * Security contract:
 *   - No tenant_id, UPN, or raw scan payloads in any request body.
 *   - Attestation submits go to pending_operator_review (operator must approve).
 *   - All reads are governance:read gated at the backend.
 *   - Writes (attestation POST, verify POST) are explicitly enumerated here.
 */

const BASE = '/api/core';

export class PortalApiError extends Error {
  constructor(
    public readonly status: number,
    public readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = 'PortalApiError';
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    ...init,
    cache: 'no-store',
    headers: {
      'Content-Type': 'application/json',
      ...(init?.headers as Record<string, string> | undefined),
    },
  });
  if (!res.ok) {
    let code = `HTTP_${res.status}`;
    try {
      const body = await res.json();
      if (typeof body?.code === 'string') code = body.code;
    } catch {
      // ignore parse errors
    }
    throw new PortalApiError(res.status, code, `API error ${res.status}`);
  }
  return res.json() as Promise<T>;
}

async function requestBlob(path: string): Promise<Blob> {
  const res = await fetch(`${BASE}${path}`, { cache: 'no-store' });
  if (!res.ok) {
    throw new PortalApiError(res.status, `HTTP_${res.status}`, `Download error ${res.status}`);
  }
  return res.blob();
}

// ─── Types ────────────────────────────────────────────────────────────────────

export interface EngagementSummary {
  id: string;
  client_name: string;
  assessment_type: string;
  status: string;
  created_at: string;
  updated_at: string;
}

export interface EngagementListResponse {
  items: EngagementSummary[];
  cursor: string | null;
  total_count: number;
}

export interface FindingSummary {
  finding_id: string;
  title: string;
  finding_type: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  status: string;
  framework_mappings: string[];
  nist_ai_rmf_mappings: string[];
  remediation_hint: string | null;
  created_at: string;
}

export interface FindingListResponse {
  items: FindingSummary[];
  total_count: number;
}

export interface ReportVersionSummary {
  report_id: string;
  version: number;
  report_type: string | null;
  status: string;
  compiled_at: string;
  compiled_by: string | null;
}

export interface ReportVersionListResponse {
  items: ReportVersionSummary[];
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
  verified_at: string | null;
}

export interface GovernanceAsset {
  asset_id: string;
  asset_name: string;
  asset_type: string;
  risk_tier: string;
  status: string;
  last_attested_at: string | null;
  next_attestation_due: string | null;
  owner_email: string | null;
}

export interface GovernanceAssetListResponse {
  items: GovernanceAsset[];
  total: number;
}

export interface AttestationRecord {
  attestation_id: string;
  asset_id: string;
  attestation_type: string;
  status: string;
  statement: string;
  notes: string | null;
  owner_email: string;
  effective_from: string | null;
  effective_until: string | null;
  attested_at: string;
}

export interface SubmitAttestationPayload {
  owner_email: string;
  attestation_type: string;
  statement: string;
  notes?: string;
}

export interface AttestationHealthSummary {
  compliant: number;
  due_soon: number;
  overdue: number;
  never_attested: number;
  total: number;
  health_pct: number;
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
  generated_at: string;
  schema_version: string;
}

export interface ContinuityGap {
  asset_id: string;
  asset_type: string;
  asset_name: string;
  risk_tier: string;
  days_overdue: number;
  staleness_index: number;
}

export interface ContinuityGapsResponse {
  items: ContinuityGap[];
  total: number;
}

// ─── API Client ───────────────────────────────────────────────────────────────

export const portalApi = {
  // Engagements
  listEngagements(params?: { limit?: number; offset?: number }): Promise<EngagementListResponse> {
    const qs = new URLSearchParams();
    if (params?.limit != null) qs.set('limit', String(params.limit));
    if (params?.offset != null) qs.set('offset', String(params.offset));
    const q = qs.toString();
    return request(`/field-assessment/engagements${q ? `?${q}` : ''}`);
  },

  // Findings (read-only)
  listFindings(
    engagementId: string,
    params?: { severity?: string; status?: string; limit?: number; offset?: number },
  ): Promise<FindingListResponse> {
    const qs = new URLSearchParams();
    if (params?.severity) qs.set('severity', params.severity);
    if (params?.status) qs.set('status', params.status);
    if (params?.limit != null) qs.set('limit', String(params.limit));
    if (params?.offset != null) qs.set('offset', String(params.offset));
    const q = qs.toString();
    return request(`/field-assessment/engagements/${engagementId}/findings${q ? `?${q}` : ''}`);
  },

  // Reports
  listReports(
    engagementId: string,
    params?: { limit?: number; offset?: number },
  ): Promise<ReportVersionListResponse> {
    const qs = new URLSearchParams();
    if (params?.limit != null) qs.set('limit', String(params.limit));
    if (params?.offset != null) qs.set('offset', String(params.offset));
    const q = qs.toString();
    return request(`/field-assessment/engagements/${engagementId}/reports${q ? `?${q}` : ''}`);
  },

  getReport(engagementId: string, version: number): Promise<ReportDocument> {
    return request(`/field-assessment/engagements/${engagementId}/reports/${version}`);
  },

  exportReport(engagementId: string, version: number, format: 'json' | 'pdf'): Promise<Blob> {
    return requestBlob(
      `/field-assessment/engagements/${engagementId}/reports/${version}/export?format=${format}`,
    );
  },

  verifyReport(engagementId: string, version: number): Promise<ReportVerifyResult> {
    return request(`/field-assessment/engagements/${engagementId}/reports/${version}/verify`, {
      method: 'POST',
    });
  },

  // Governance Assets
  listAssets(params?: { limit?: number; offset?: number }): Promise<GovernanceAsset[]> {
    const qs = new URLSearchParams();
    if (params?.limit != null) qs.set('limit', String(params.limit));
    if (params?.offset != null) qs.set('offset', String(params.offset));
    const q = qs.toString();
    return request(`/governance/assets${q ? `?${q}` : ''}`);
  },

  listAttestations(assetId: string): Promise<AttestationRecord[]> {
    return request(`/governance/assets/${assetId}/attestations`);
  },

  submitAttestation(
    assetId: string,
    payload: SubmitAttestationPayload,
  ): Promise<AttestationRecord> {
    return request(`/governance/assets/${assetId}/attestations`, {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  },

  // Continuity
  getAttestationHealth(): Promise<AttestationHealthSummary> {
    return request('/governance/assets/attestation-health');
  },

  explainFinding(engagementId: string, findingId: string): Promise<FindingExplanation> {
    return request(
      `/field-assessment/engagements/${engagementId}/findings/${findingId}/explain`,
    );
  },

  listContinuityGaps(params?: {
    risk_tier?: string;
    days_overdue_min?: number;
  }): Promise<ContinuityGapsResponse> {
    const qs = new URLSearchParams();
    if (params?.risk_tier) qs.set('risk_tier', params.risk_tier);
    if (params?.days_overdue_min != null)
      qs.set('days_overdue_min', String(params.days_overdue_min));
    const q = qs.toString();
    return request(`/governance/assets/continuity-gaps${q ? `?${q}` : ''}`);
  },
} as const;
