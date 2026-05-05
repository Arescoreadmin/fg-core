/**
 * Report API client — all requests go through fg-core's single API.
 * The Next.js proxy at /api/core/* forwards to admin-gateway → fg-core.
 * Routes are prefixed /assessment/reports/* on the backend (api/reports_engine.py).
 */

const BASE = '/api/core/assessment';

export type ReportStatus = 'pending' | 'generating' | 'complete' | 'failed';

export interface RoadmapItem {
  title: string;
  description: string;
  effort: string;
  impact: string;
}

export interface Roadmap {
  days_30: RoadmapItem[];
  days_60: RoadmapItem[];
  days_90: RoadmapItem[];
}

export interface FrameworkAlignment {
  framework: string;
  alignment_pct: number;
  gap_count: number;
  notes: string;
}

export interface ReportContent {
  executive_summary: string;
  key_strengths: string[];
  critical_gaps: string[];
  domain_findings: Record<string, string>;
  roadmap: Roadmap;
  framework_alignments: FrameworkAlignment[];
  disclaimer: string;
}

export interface Report {
  id: string;
  assessment_id: string;
  org_id: string;
  status: ReportStatus;
  prompt_type: string;
  content: ReportContent | null;
  error_message: string | null;
  created_at: string;
  completed_at: string | null;
}

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    headers: { 'Content-Type': 'application/json' },
    ...options,
  });
  if (!res.ok) {
    const body = await res.text().catch(() => '');
    throw new Error(`Report API ${res.status}: ${body}`);
  }
  return res.json() as Promise<T>;
}

export const reportApi = {
  generate: (
    assessmentId: string,
    promptType: 'executive' | 'technical' | 'compliance' = 'executive'
  ) =>
    request<{ report_id: string; status: ReportStatus }>('/reports/generate', {
      method: 'POST',
      body: JSON.stringify({ assessment_id: assessmentId, prompt_type: promptType }),
    }),

  getReport: (id: string) => request<Report>(`/reports/${id}`),

  getDownloadUrl: (id: string) =>
    request<{ url: string | null; expires_in: number; message?: string }>(
      `/reports/${id}/download`
    ),
};
