/**
 * Service Credentials Administration — Console API client (P-113.4).
 *
 * All calls proxy through /api/core → admin/tenants/.../credential-administration.
 * Fail-closed: any non-2xx, network error, or parse failure returns { ok: false, error }.
 * Plaintext secrets are never stored — callers must display and discard immediately.
 */

export type CredentialStatus = 'active' | 'suspended' | 'revoked' | 'rotated' | 'expired';

export interface ServiceCredential {
  credential_id: string;
  name: string | null;
  status: CredentialStatus;
  credential_slot: string;
  generation: number;
  issued_at: string | null;
  expires_at: string | null;
  last_used_at: string | null;
  approximate_use_count: number;
  role: string | null;
}

export interface IssuedCredential extends ServiceCredential {
  plaintext_secret: string | null;
}

export interface RotatedCredential extends ServiceCredential {
  plaintext_secret: string | null;
  rotated_from_credential_id: string;
}

export type SafeResult<T> =
  | { ok: true; data: T }
  | { ok: false; error: string; status?: number };

function baseUrl(tenantId: string): string {
  return `/api/core/admin/tenants/${encodeURIComponent(tenantId)}/credential-administration`;
}

function tenantQs(tenantId: string): string {
  return `tenant_id=${encodeURIComponent(tenantId)}`;
}

async function call<T>(url: string, init?: RequestInit): Promise<SafeResult<T>> {
  try {
    const res = await fetch(url, {
      ...init,
      headers: { 'Content-Type': 'application/json', ...init?.headers },
      cache: 'no-store',
    });
    let payload: unknown = null;
    const text = await res.text();
    if (text) {
      try { payload = JSON.parse(text); } catch { payload = null; }
    }
    if (!res.ok) {
      const msg =
        payload && typeof payload === 'object' && payload !== null
          ? ((payload as Record<string, unknown>).detail as string | undefined) ??
            `HTTP ${res.status}`
          : `HTTP ${res.status}`;
      return { ok: false, error: String(msg), status: res.status };
    }
    return { ok: true, data: payload as T };
  } catch {
    return { ok: false, error: 'Network error' };
  }
}

export async function listServiceCredentials(
  tenantId: string,
): Promise<SafeResult<{ items: ServiceCredential[]; total: number }>> {
  return call(`${baseUrl(tenantId)}?${tenantQs(tenantId)}`);
}

export async function issueServiceCredential(
  tenantId: string,
  name: string,
): Promise<SafeResult<IssuedCredential>> {
  return call(`${baseUrl(tenantId)}?${tenantQs(tenantId)}`, {
    method: 'POST',
    body: JSON.stringify({ name }),
  });
}

export async function getServiceCredential(
  tenantId: string,
  credentialId: string,
): Promise<SafeResult<ServiceCredential>> {
  return call(
    `${baseUrl(tenantId)}/${encodeURIComponent(credentialId)}?${tenantQs(tenantId)}`,
  );
}

export async function rotateServiceCredential(
  tenantId: string,
  credentialId: string,
): Promise<SafeResult<RotatedCredential>> {
  return call(
    `${baseUrl(tenantId)}/${encodeURIComponent(credentialId)}/rotate?${tenantQs(tenantId)}`,
    { method: 'POST' },
  );
}

export async function revokeServiceCredential(
  tenantId: string,
  credentialId: string,
): Promise<SafeResult<{ revoked: boolean }>> {
  return call(
    `${baseUrl(tenantId)}/${encodeURIComponent(credentialId)}?${tenantQs(tenantId)}`,
    { method: 'DELETE' },
  );
}

export async function suspendServiceCredential(
  tenantId: string,
  credentialId: string,
): Promise<SafeResult<ServiceCredential>> {
  return call(
    `${baseUrl(tenantId)}/${encodeURIComponent(credentialId)}/suspend?${tenantQs(tenantId)}`,
    { method: 'POST' },
  );
}

export async function resumeServiceCredential(
  tenantId: string,
  credentialId: string,
): Promise<SafeResult<ServiceCredential>> {
  return call(
    `${baseUrl(tenantId)}/${encodeURIComponent(credentialId)}/resume?${tenantQs(tenantId)}`,
    { method: 'POST' },
  );
}

export async function assignServiceCredentialRole(
  tenantId: string,
  credentialId: string,
  role: string,
): Promise<SafeResult<Record<string, unknown>>> {
  return call(
    `${baseUrl(tenantId)}/${encodeURIComponent(credentialId)}/role?${tenantQs(tenantId)}`,
    { method: 'PUT', body: JSON.stringify({ role }) },
  );
}
