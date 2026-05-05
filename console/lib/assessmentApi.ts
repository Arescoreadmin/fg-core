/**
 * Assessment API client — all requests go through fg-core's single API.
 * The Next.js proxy at /api/core/* forwards to admin-gateway → fg-core.
 * Routes are prefixed /assessment/* on the backend (api/assessments.py).
 */

const BASE = '/api/core/assessment';

export interface OrgCreatePayload {
  name: string;
  email?: string;
  industry: string;
  employee_count: string;
  revenue: string;
  handles_phi: boolean;
  handles_cui: boolean;
  is_dod_contractor: boolean;
  fedramp_required: boolean;
}

export interface OrgCreateResponse {
  org_id: string;
  assessment_id: string;
  profile_type: string;
  schema_version: string;
}

export interface CheckoutResponse {
  checkout_url: string | null;
  assessment_id: string;
  dev_bypass?: boolean;
  already_paid?: boolean;
}

export interface AssessmentQuestion {
  id: string;
  domain: string;
  text: string;
  type: 'boolean' | 'scale' | 'select' | 'text';
  options?: string[];
  weight: number;
}

export interface AssessmentDetail {
  id: string;
  org_id: string;
  status: 'draft' | 'in_progress' | 'submitted' | 'scored';
  profile_type: string;
  responses: Record<string, unknown>;
  scores: Record<string, number> | null;
  overall_score: number | null;
  risk_band: 'critical' | 'high' | 'medium' | 'low' | null;
  payment_status: 'unpaid' | 'paid';
  tier: string | null;
}

export interface SubmitResponse {
  assessment_id: string;
  overall_score: number;
  risk_band: 'critical' | 'high' | 'medium' | 'low';
  domain_scores: Record<string, number>;
}

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    headers: { 'Content-Type': 'application/json' },
    ...options,
  });
  if (!res.ok) {
    const body = await res.text().catch(() => '');
    throw new Error(`Assessment API ${res.status}: ${body}`);
  }
  return res.json() as Promise<T>;
}

export const assessmentApi = {
  createOrg: (payload: OrgCreatePayload) =>
    request<OrgCreateResponse>('/orgs', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  createCheckout: (assessmentId: string) =>
    request<CheckoutResponse>(`/assessments/${assessmentId}/checkout`, {
      method: 'POST',
    }),

  getAssessment: (id: string) =>
    request<AssessmentDetail>(`/assessments/${id}`),

  getQuestions: (id: string) =>
    request<AssessmentQuestion[]>(`/assessments/${id}/questions`),

  saveResponses: (id: string, responses: Record<string, unknown>) =>
    request<{ saved: boolean; response_count: number }>(
      `/assessments/${id}/responses`,
      {
        method: 'PATCH',
        body: JSON.stringify({ responses }),
      }
    ),

  submitAssessment: (id: string) =>
    request<SubmitResponse>(`/assessments/${id}/submit`, {
      method: 'POST',
    }),
};
