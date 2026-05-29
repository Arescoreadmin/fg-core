/**
 * workforceApi.ts — Console API client for Workforce Intelligence (PR 36)
 */

const BASE = '/api/core';

async function req<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    ...init,
    cache: 'no-store',
    headers: { 'Content-Type': 'application/json', ...(init?.headers as Record<string, string>) },
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body?.detail?.message ?? body?.detail ?? `HTTP ${res.status}`);
  }
  return res.json();
}

// ─── Types ────────────────────────────────────────────────────────────────────

export interface TenantUser {
  user_id: string;
  email: string;
  display_name: string;
  role: string;
  active: boolean;
  invite_pending: boolean;
  last_active_at: string | null;
  created_at: string;
}

export interface InviteResult {
  user_id: string;
  email: string;
  display_name: string;
  role: string;
  invite_token: string;
  invite_expires_at: string;
  invite_url_hint: string;
}

export interface RiskProfile {
  user_id: string;
  email: string;
  display_name: string;
  role: string;
  last_active_at: string | null;
  risk_score: number;
  risk_band: 'low' | 'medium' | 'high' | 'critical';
  total_queries: number;
  policy_violations: number;
  personal_ratio: number;
  sensitive_topic_count: number;
  pii_query_count: number;
  competitor_query_count: number;
  active_days: number;
  period_days: number;
}

export interface QueryRecord {
  id: string;
  session_id: string | null;
  query_text: string;
  response_text: string | null;
  provider: string | null;
  model: string | null;
  prompt_tokens: number;
  completion_tokens: number;
  policy_decision: string;
  subject_category: string | null;
  work_relevance: string | null;
  sensitivity_flags: string[];
  classified_at: string | null;
  created_at: string;
}

export interface UserActivity {
  user: { user_id: string; email: string; display_name: string; role: string };
  risk_profile: RiskProfile;
  queries: QueryRecord[];
  total: number;
}

// ─── API ──────────────────────────────────────────────────────────────────────

export const workforceApi = {
  listUsers(): Promise<{ items: TenantUser[]; total: number }> {
    return req('/workforce/users');
  },

  inviteUser(payload: {
    email: string;
    display_name: string;
    role: string;
  }): Promise<InviteResult> {
    return req('/workforce/users', { method: 'POST', body: JSON.stringify(payload) });
  },

  updateUser(
    userId: string,
    payload: { active?: boolean; role?: string; display_name?: string },
  ): Promise<{ ok: boolean }> {
    return req(`/workforce/users/${userId}`, { method: 'PATCH', body: JSON.stringify(payload) });
  },

  listRiskProfiles(): Promise<{ items: RiskProfile[]; total: number; period_days: number }> {
    return req('/workforce/risk-profiles');
  },

  getUserActivity(
    userId: string,
    params?: { limit?: number; offset?: number },
  ): Promise<UserActivity> {
    const qs = new URLSearchParams();
    if (params?.limit != null) qs.set('limit', String(params.limit));
    if (params?.offset != null) qs.set('offset', String(params.offset));
    const q = qs.toString();
    return req(`/workforce/users/${userId}/activity${q ? `?${q}` : ''}`);
  },
} as const;
