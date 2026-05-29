'use client';

import { useEffect, useState } from 'react';
import {
  workforceApi,
  type TenantUser,
  type RiskProfile,
  type UserActivity,
  type QueryRecord,
} from '@/lib/workforceApi';

// ─── Style maps ───────────────────────────────────────────────────────────────

const BAND_CLASS: Record<string, string> = {
  low:      'border-green-500/30 bg-green-500/5 text-green-300',
  medium:   'border-amber-500/30 bg-amber-500/5 text-amber-200',
  high:     'border-orange-500/30 bg-orange-500/5 text-orange-300',
  critical: 'border-red-500/30 bg-red-500/5 text-red-300',
};

const DECISION_CLASS: Record<string, string> = {
  allow:  'text-green-300',
  block:  'text-red-300',
  redact: 'text-amber-200',
};

const RELEVANCE_CLASS: Record<string, string> = {
  on_task:   'text-green-300',
  tangential:'text-amber-200',
  personal:  'text-red-300',
};

function RiskBadge({ band }: { band: string }) {
  const cls = BAND_CLASS[band] ?? 'border-border bg-surface-3 text-muted';
  return (
    <span className={`inline-flex items-center rounded px-1.5 py-0.5 text-xs border font-medium ${cls}`}>
      {band.charAt(0).toUpperCase() + band.slice(1)}
    </span>
  );
}

function fmtDate(iso: string | null) {
  if (!iso) return '—';
  return new Date(iso).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
}

function fmtDateTime(iso: string | null) {
  if (!iso) return '—';
  return new Date(iso).toLocaleString('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

// ─── Invite modal ─────────────────────────────────────────────────────────────

function InviteModal({
  onClose,
  onInvited,
}: {
  onClose: () => void;
  onInvited: (token: string, email: string) => void;
}) {
  const [email, setEmail] = useState('');
  const [name, setName] = useState('');
  const [role, setRole] = useState('user');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  async function submit() {
    if (!email || !name) { setError('Email and name are required.'); return; }
    setLoading(true);
    setError('');
    try {
      const result = await workforceApi.inviteUser({ email, display_name: name, role });
      onInvited(result.invite_token, result.email);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed to send invite.');
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
      <div className="w-full max-w-md rounded-xl border border-border bg-surface p-6 space-y-4">
        <h2 className="text-sm font-semibold text-foreground">Invite User</h2>
        {error && <p className="text-xs text-red-300">{error}</p>}
        <div className="space-y-3">
          {[
            { label: 'Email', value: email, set: setEmail, type: 'email' },
            { label: 'Display Name', value: name, set: setName, type: 'text' },
          ].map(({ label, value, set, type }) => (
            <div key={label}>
              <label className="block text-xs text-muted mb-1">{label}</label>
              <input
                type={type}
                value={value}
                onChange={(e) => set(e.target.value)}
                className="w-full rounded border border-border bg-surface-2 px-3 py-2 text-sm text-foreground focus:outline-none focus:border-primary/60"
              />
            </div>
          ))}
          <div>
            <label className="block text-xs text-muted mb-1">Role</label>
            <select
              value={role}
              onChange={(e) => setRole(e.target.value)}
              className="w-full rounded border border-border bg-surface-2 px-3 py-2 text-sm text-foreground focus:outline-none focus:border-primary/60"
            >
              <option value="user">User</option>
              <option value="auditor">Auditor</option>
              <option value="admin">Admin</option>
            </select>
          </div>
        </div>
        <div className="flex gap-2 justify-end">
          <button onClick={onClose} className="px-3 py-1.5 text-xs text-muted hover:text-foreground">
            Cancel
          </button>
          <button
            onClick={submit}
            disabled={loading}
            className="rounded border border-primary bg-primary/10 px-4 py-1.5 text-xs font-medium text-primary hover:bg-primary/20 disabled:opacity-50"
          >
            {loading ? 'Sending…' : 'Send Invite'}
          </button>
        </div>
      </div>
    </div>
  );
}

// ─── User activity drawer ─────────────────────────────────────────────────────

function ActivityDrawer({
  userId,
  onClose,
}: {
  userId: string;
  onClose: () => void;
}) {
  const [activity, setActivity] = useState<UserActivity | null>(null);
  const [loading, setLoading] = useState(true);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());

  useEffect(() => {
    workforceApi
      .getUserActivity(userId, { limit: 50 })
      .then(setActivity)
      .catch(() => {})
      .finally(() => setLoading(false));
  }, [userId]);

  function toggleExpand(id: string) {
    setExpanded((prev) => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });
  }

  return (
    <div className="fixed inset-0 z-50 flex justify-end">
      <div className="absolute inset-0 bg-black/50" onClick={onClose} />
      <div className="relative z-10 w-full max-w-2xl flex flex-col bg-surface border-l border-border overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between border-b border-border px-5 py-3">
          <div>
            <p className="text-sm font-semibold text-foreground">
              {activity?.user.display_name ?? 'User Activity'}
            </p>
            <p className="text-xs text-muted">{activity?.user.email}</p>
          </div>
          {activity && (
            <RiskBadge band={activity.risk_profile.risk_band} />
          )}
          <button onClick={onClose} className="ml-4 text-muted hover:text-foreground text-sm">✕</button>
        </div>

        {loading && (
          <div className="flex-1 flex items-center justify-center text-sm text-muted">Loading…</div>
        )}

        {activity && (
          <div className="flex-1 overflow-y-auto p-5 space-y-5">
            {/* Risk summary */}
            <div className="grid grid-cols-3 gap-3">
              {[
                { label: 'Risk Score', value: `${activity.risk_profile.risk_score}/100` },
                { label: 'Total Queries', value: activity.risk_profile.total_queries },
                { label: 'Policy Violations', value: activity.risk_profile.policy_violations },
                { label: 'Personal Ratio', value: `${Math.round(activity.risk_profile.personal_ratio * 100)}%` },
                { label: 'Sensitive Topics', value: activity.risk_profile.sensitive_topic_count },
                { label: 'PII Detected', value: activity.risk_profile.pii_query_count },
              ].map(({ label, value }) => (
                <div key={label} className="rounded border border-border bg-surface-2 px-3 py-2">
                  <p className="text-[10px] text-muted">{label}</p>
                  <p className="mt-0.5 text-sm font-semibold text-foreground">{value}</p>
                </div>
              ))}
            </div>

            {/* Query log */}
            <div>
              <p className="text-xs font-medium text-muted mb-2">
                Query History ({activity.total} total · showing {activity.queries.length})
              </p>
              {activity.queries.length === 0 && (
                <p className="text-xs text-muted">No queries recorded in this period.</p>
              )}
              <div className="space-y-2">
                {activity.queries.map((q: QueryRecord) => (
                  <div key={q.id} className="rounded border border-border bg-surface p-3 space-y-1.5">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className={`text-xs font-medium ${DECISION_CLASS[q.policy_decision] ?? 'text-muted'}`}>
                        {q.policy_decision.toUpperCase()}
                      </span>
                      {q.subject_category && (
                        <span className="text-xs border border-border rounded px-1 py-0.5 text-muted">
                          {q.subject_category}
                        </span>
                      )}
                      {q.work_relevance && (
                        <span className={`text-xs ${RELEVANCE_CLASS[q.work_relevance] ?? 'text-muted'}`}>
                          {q.work_relevance.replace('_', ' ')}
                        </span>
                      )}
                      <span className="ml-auto text-xs text-muted">{fmtDateTime(q.created_at)}</span>
                    </div>
                    <p className="text-xs text-foreground line-clamp-2">{q.query_text}</p>
                    {q.sensitivity_flags.length > 0 && (
                      <div className="flex flex-wrap gap-1">
                        {q.sensitivity_flags.map((f) => (
                          <span key={f} className="text-[10px] border border-red-500/30 bg-red-500/5 text-red-300 rounded px-1 py-0.5">
                            {f.replace(/_/g, ' ')}
                          </span>
                        ))}
                      </div>
                    )}
                    {q.response_text && (
                      <button
                        onClick={() => toggleExpand(q.id)}
                        className="text-xs text-muted hover:text-foreground underline underline-offset-2"
                      >
                        {expanded.has(q.id) ? 'Hide response ↑' : 'Show response ↓'}
                      </button>
                    )}
                    {expanded.has(q.id) && q.response_text && (
                      <p className="text-xs text-muted leading-relaxed border-t border-border pt-1.5 mt-1">
                        {q.response_text.slice(0, 500)}{q.response_text.length > 500 ? '…' : ''}
                      </p>
                    )}
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

// ─── Page ─────────────────────────────────────────────────────────────────────

type Tab = 'risk' | 'users';

export default function WorkforcePage() {
  const [tab, setTab] = useState<Tab>('risk');
  const [profiles, setProfiles] = useState<RiskProfile[]>([]);
  const [users, setUsers] = useState<TenantUser[]>([]);
  const [loading, setLoading] = useState(true);
  const [showInvite, setShowInvite] = useState(false);
  const [inviteResult, setInviteResult] = useState<{ token: string; email: string } | null>(null);
  const [activeUserId, setActiveUserId] = useState<string | null>(null);

  function loadData() {
    setLoading(true);
    Promise.allSettled([
      workforceApi.listRiskProfiles(),
      workforceApi.listUsers(),
    ]).then(([rRes, uRes]) => {
      if (rRes.status === 'fulfilled') setProfiles(rRes.value.items);
      if (uRes.status === 'fulfilled') setUsers(uRes.value.items);
      setLoading(false);
    });
  }

  useEffect(() => { loadData(); }, []);

  const criticalCount = profiles.filter((p) => p.risk_band === 'critical').length;
  const highCount = profiles.filter((p) => p.risk_band === 'high').length;

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-semibold text-foreground">Workforce Intelligence</h1>
          <p className="text-sm text-muted mt-0.5">
            Per-user AI activity monitoring and risk profiling
          </p>
        </div>
        <button
          onClick={() => setShowInvite(true)}
          className="rounded border border-primary bg-primary/10 px-4 py-2 text-xs font-medium text-primary hover:bg-primary/20"
        >
          + Invite User
        </button>
      </div>

      {/* Alert strip */}
      {(criticalCount > 0 || highCount > 0) && (
        <div className="rounded border border-red-500/30 bg-red-500/5 px-4 py-3 flex items-center gap-3">
          <span className="text-sm text-red-300 font-medium">
            {criticalCount > 0 && `${criticalCount} critical`}
            {criticalCount > 0 && highCount > 0 && ', '}
            {highCount > 0 && `${highCount} high`}
            {' '}risk user{(criticalCount + highCount) !== 1 ? 's' : ''} in the last 30 days
          </span>
          <button onClick={() => setTab('risk')} className="ml-auto text-xs text-red-300 underline">
            View →
          </button>
        </div>
      )}

      {/* Tabs */}
      <div className="flex gap-1 border-b border-border">
        {[
          { id: 'risk' as Tab, label: 'Risk Profiles' },
          { id: 'users' as Tab, label: 'User Management' },
        ].map((t) => (
          <button
            key={t.id}
            onClick={() => setTab(t.id)}
            className={`px-3 py-2 text-xs font-medium border-b-2 -mb-px transition-colors ${
              tab === t.id
                ? 'border-primary text-primary'
                : 'border-transparent text-muted hover:text-foreground'
            }`}
          >
            {t.label}
          </button>
        ))}
      </div>

      {loading && (
        <div className="rounded border border-border bg-surface p-8 text-center text-sm text-muted">
          Loading…
        </div>
      )}

      {/* Risk profiles tab */}
      {!loading && tab === 'risk' && (
        <div className="overflow-x-auto rounded border border-border">
          {profiles.length === 0 ? (
            <div className="p-8 text-center text-sm text-muted">
              No users have made AI queries yet. Invite users to start tracking activity.
            </div>
          ) : (
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-border bg-surface-2 text-left text-muted">
                  <th className="px-3 py-2 font-medium">User</th>
                  <th className="px-3 py-2 font-medium">Risk</th>
                  <th className="px-3 py-2 font-medium">Score</th>
                  <th className="px-3 py-2 font-medium">Queries</th>
                  <th className="px-3 py-2 font-medium">Violations</th>
                  <th className="px-3 py-2 font-medium">Personal %</th>
                  <th className="px-3 py-2 font-medium">PII Hits</th>
                  <th className="px-3 py-2 font-medium">Last Active</th>
                  <th className="px-3 py-2 font-medium"></th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {profiles.map((p) => (
                  <tr key={p.user_id} className="bg-surface hover:bg-surface-2 transition-colors">
                    <td className="px-3 py-2">
                      <p className="font-medium text-foreground">{p.display_name}</p>
                      <p className="text-muted">{p.email}</p>
                    </td>
                    <td className="px-3 py-2"><RiskBadge band={p.risk_band} /></td>
                    <td className="px-3 py-2 text-foreground font-mono">{p.risk_score}</td>
                    <td className="px-3 py-2 text-foreground">{p.total_queries}</td>
                    <td className={`px-3 py-2 font-medium ${p.policy_violations > 0 ? 'text-red-300' : 'text-muted'}`}>
                      {p.policy_violations}
                    </td>
                    <td className={`px-3 py-2 ${p.personal_ratio > 0.3 ? 'text-orange-300' : 'text-muted'}`}>
                      {Math.round(p.personal_ratio * 100)}%
                    </td>
                    <td className={`px-3 py-2 ${p.pii_query_count > 0 ? 'text-red-300' : 'text-muted'}`}>
                      {p.pii_query_count}
                    </td>
                    <td className="px-3 py-2 text-muted">{fmtDate(p.last_active_at)}</td>
                    <td className="px-3 py-2">
                      <button
                        onClick={() => setActiveUserId(p.user_id)}
                        className="text-xs text-primary hover:underline"
                      >
                        Review
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}

      {/* Users tab */}
      {!loading && tab === 'users' && (
        <div className="overflow-x-auto rounded border border-border">
          {users.length === 0 ? (
            <div className="p-8 text-center text-sm text-muted">
              No users yet. Click "Invite User" to add the first one.
            </div>
          ) : (
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-border bg-surface-2 text-left text-muted">
                  <th className="px-3 py-2 font-medium">User</th>
                  <th className="px-3 py-2 font-medium">Role</th>
                  <th className="px-3 py-2 font-medium">Status</th>
                  <th className="px-3 py-2 font-medium">Invite</th>
                  <th className="px-3 py-2 font-medium">Last Active</th>
                  <th className="px-3 py-2 font-medium">Added</th>
                  <th className="px-3 py-2 font-medium"></th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {users.map((u) => (
                  <tr key={u.user_id} className="bg-surface hover:bg-surface-2 transition-colors">
                    <td className="px-3 py-2">
                      <p className="font-medium text-foreground">{u.display_name}</p>
                      <p className="text-muted">{u.email}</p>
                    </td>
                    <td className="px-3 py-2 text-muted capitalize">{u.role}</td>
                    <td className="px-3 py-2">
                      <span className={`font-medium ${u.active ? 'text-green-300' : 'text-muted'}`}>
                        {u.active ? 'Active' : 'Inactive'}
                      </span>
                    </td>
                    <td className="px-3 py-2">
                      {u.invite_pending ? (
                        <span className="text-amber-200">Pending</span>
                      ) : (
                        <span className="text-muted">Accepted</span>
                      )}
                    </td>
                    <td className="px-3 py-2 text-muted">{fmtDate(u.last_active_at)}</td>
                    <td className="px-3 py-2 text-muted">{fmtDate(u.created_at)}</td>
                    <td className="px-3 py-2">
                      {u.active ? (
                        <button
                          onClick={async () => {
                            await workforceApi.updateUser(u.user_id, { active: false });
                            loadData();
                          }}
                          className="text-xs text-red-400 hover:text-red-300"
                        >
                          Deactivate
                        </button>
                      ) : (
                        <button
                          onClick={async () => {
                            await workforceApi.updateUser(u.user_id, { active: true });
                            loadData();
                          }}
                          className="text-xs text-green-400 hover:text-green-300"
                        >
                          Reactivate
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}

      {/* Invite result */}
      {inviteResult && (
        <div className="rounded border border-green-500/30 bg-green-500/5 p-4 space-y-2">
          <p className="text-sm font-medium text-green-300">Invite created for {inviteResult.email}</p>
          <p className="text-xs text-muted">Share this link with the user (single-use, 72 hr expiry):</p>
          <code className="block text-xs bg-surface-2 border border-border rounded px-2 py-1.5 text-foreground break-all">
            {typeof window !== 'undefined'
              ? `${window.location.protocol}//${window.location.host.replace('console.', 'app.')}/accept-invite?token=${inviteResult.token}`
              : `/accept-invite?token=${inviteResult.token}`}
          </code>
          <button onClick={() => setInviteResult(null)} className="text-xs text-muted hover:text-foreground">
            Dismiss
          </button>
        </div>
      )}

      {/* Modals */}
      {showInvite && (
        <InviteModal
          onClose={() => setShowInvite(false)}
          onInvited={(token, email) => {
            setShowInvite(false);
            setInviteResult({ token, email });
            loadData();
          }}
        />
      )}
      {activeUserId && (
        <ActivityDrawer userId={activeUserId} onClose={() => setActiveUserId(null)} />
      )}
    </div>
  );
}
