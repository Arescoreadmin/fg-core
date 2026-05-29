/**
 * workforceApi.ts — Console API client for Workforce Intelligence (PR 36 + 37)
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

export interface RiskSnapshot {
  date: string;
  risk_score: number;
  risk_band: string;
  total_queries: number;
  policy_violations: number;
  personal_ratio: number;
}

export interface TenantKeyword {
  id: string;
  keyword: string;
  match_type: 'contains' | 'exact' | 'word_boundary' | 'prefix' | 'regex';
  case_sensitive: boolean;
  flag_value: string;
  flag_type: 'sensitivity' | 'subject' | 'custom';
  action: 'flag' | 'block' | 'escalate';
  description: string | null;
  created_by: string | null;
  created_at: string;
}

export interface AlertRule {
  id: string;
  name: string;
  threshold_score: number | null;
  threshold_band: string | null;
  cooldown_hours: number;
  active: boolean;
  created_at: string;
}

export interface FiredAlert {
  id: string;
  rule_id: string;
  rule_name: string;
  user_id: string;
  user_email: string | null;
  risk_score: number;
  risk_band: string;
  dismissed: boolean;
  dismissed_at: string | null;
  fired_at: string;
}

export interface BacktestResult {
  matched: number;
  scanned: number;
  matches: Array<{
    query_id: string;
    query_text: string;
    user_id: string;
    created_at: string;
  }>;
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

  getRiskHistory(userId: string, days = 30): Promise<{ user_id: string; history: RiskSnapshot[]; period_days: number }> {
    return req(`/workforce/users/${userId}/risk-history?days=${days}`);
  },

  listKeywords(): Promise<{ items: TenantKeyword[]; total: number }> {
    return req('/workforce/keywords');
  },

  createKeyword(payload: {
    keyword: string;
    match_type: string;
    case_sensitive: boolean;
    flag_value: string;
    flag_type: string;
    action: string;
    description?: string;
  }): Promise<{ id: string; ok: boolean }> {
    return req('/workforce/keywords', { method: 'POST', body: JSON.stringify(payload) });
  },

  deleteKeyword(keywordId: string): Promise<{ ok: boolean }> {
    return req(`/workforce/keywords/${keywordId}`, { method: 'DELETE' });
  },

  previewKeyword(payload: {
    keyword: string;
    match_type: string;
    case_sensitive: boolean;
    limit?: number;
  }): Promise<BacktestResult> {
    return req('/workforce/keywords/preview', { method: 'POST', body: JSON.stringify(payload) });
  },

  listAlertRules(): Promise<{ items: AlertRule[]; total: number }> {
    return req('/workforce/alert-rules');
  },

  createAlertRule(payload: {
    name: string;
    threshold_score?: number | null;
    threshold_band?: string | null;
    cooldown_hours?: number;
    active?: boolean;
  }): Promise<{ id: string; ok: boolean }> {
    return req('/workforce/alert-rules', { method: 'POST', body: JSON.stringify(payload) });
  },

  updateAlertRule(
    ruleId: string,
    payload: { name: string; threshold_score?: number | null; threshold_band?: string | null; cooldown_hours?: number; active?: boolean },
  ): Promise<{ ok: boolean }> {
    return req(`/workforce/alert-rules/${ruleId}`, { method: 'PATCH', body: JSON.stringify(payload) });
  },

  deleteAlertRule(ruleId: string): Promise<{ ok: boolean }> {
    return req(`/workforce/alert-rules/${ruleId}`, { method: 'DELETE' });
  },

  listAlerts(dismissed = false, limit = 50): Promise<{ items: FiredAlert[]; total: number }> {
    return req(`/workforce/alerts?dismissed=${dismissed}&limit=${limit}`);
  },

  dismissAlert(alertId: string): Promise<{ ok: boolean }> {
    return req(`/workforce/alerts/${alertId}/dismiss`, { method: 'POST' });
  },
} as const;
