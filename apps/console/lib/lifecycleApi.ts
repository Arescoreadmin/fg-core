/**
 * Client Lifecycle Control Plane — Console API client (CLIENT-LIFECYCLE-002).
 *
 * All calls proxy through /api/core → admin/tenants/.../lifecycle on the Core API.
 * Fail-closed: any non-2xx response, unknown lifecycle_version, or network error
 * returns { ok: false, error } — never returns { ok: true } with degraded data.
 */

// ── Version contract ──────────────────────────────────────────────────────────

/** The only lifecycle_version this client understands. Any other value → fail closed. */
export const EXPECTED_LIFECYCLE_VERSION = 1;

// ── Types ─────────────────────────────────────────────────────────────────────

export type LifecycleState =
  | 'operational'
  | 'admin_unset'
  | 'admin_unbound'
  | 'tenant_suspended'
  | 'tenant_not_found';

export interface ClientLifecycle {
  lifecycle_version: number;
  tenant_id: string;
  lifecycle_state: LifecycleState;
  operational: boolean;
  repairable: boolean;
  blockers: string[];
  warnings: string[];
  next_actions: string[];
  diagnostics: {
    tenant_canonical_state: string | null;
    has_bound_admin: boolean;
    active_member_count: number;
  };
}

export type SafeLifecycleResult =
  | { ok: true; data: ClientLifecycle }
  | { ok: false; error: string };

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Fetch the canonical lifecycle state for a tenant.
 *
 * Fail-closed invariants:
 *   - Non-2xx response → { ok: false, error: message }
 *   - lifecycle_version !== EXPECTED_LIFECYCLE_VERSION → { ok: false, error: 'Unsupported lifecycle_version: N' }
 *   - Network/parse error → { ok: false, error: 'Network error' }
 *   - Only returns { ok: true, data } when ALL guards pass
 */
export async function getClientLifecycle(tenantId: string): Promise<SafeLifecycleResult> {
  try {
    const url = `/api/core/admin/tenants/${encodeURIComponent(tenantId)}/lifecycle?tenant_id=${encodeURIComponent(tenantId)}`;
    const response = await fetch(url, { cache: 'no-store' });

    let payload: unknown = null;
    const text = await response.text();
    if (text) {
      try { payload = JSON.parse(text); } catch { payload = null; }
    }

    if (!response.ok) {
      const msg =
        payload && typeof payload === 'object' && payload !== null && 'detail' in payload
          ? String((payload as Record<string, unknown>).detail)
          : `HTTP ${response.status}`;
      return { ok: false, error: msg };
    }

    const data = payload as ClientLifecycle;

    // L2-13 invariant: unknown lifecycle_version → fail closed
    if (data.lifecycle_version !== EXPECTED_LIFECYCLE_VERSION) {
      return { ok: false, error: `Unsupported lifecycle_version: ${data.lifecycle_version}` };
    }

    return { ok: true, data };
  } catch {
    return { ok: false, error: 'Network error' };
  }
}
