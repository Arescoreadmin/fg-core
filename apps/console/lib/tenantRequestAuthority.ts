import {
  resolveTenantRequestAuthority,
  type TenantRequestAuthorityResolution,
} from '@/lib/consoleAccess';
import { getTenantApiKey } from '@/lib/tenant-registry';
import { internalGatewaySecret } from '@/lib/internal-gateway-secret';

const TENANT_ID_RE = /^[a-zA-Z0-9_-]{1,128}$/;
const PROD_LIKE_FG_ENVS = new Set(['prod', 'production', 'staging']);
const CORE_API_URL = (process.env.CORE_API_URL || 'http://localhost:8000').replace(/\/$/, '');
const OPERATOR_AUTHORITY_CACHE_MS = 30_000;

type OperatorAuthorityValidation =
  | { ok: true }
  | { ok: false; status: number; code: string; message: string };

let operatorAuthorityCache: {
  tenantId: string;
  result: OperatorAuthorityValidation;
  expiresAt: number;
} | null = null;

export type TenantCredentialResolution =
  | {
      ok: true;
      tenantId: string;
      apiKey: string;
      authority: 'tenant_human' | 'internal_console';
      source: 'session' | 'requested' | 'configured_operator';
    }
  | {
      ok: false;
      status: number;
      code: string;
      message: string;
    };

function isProdLikeEnv(): boolean {
  const nodeEnv = (process.env.NODE_ENV || '').trim().toLowerCase();
  const fgEnv = (process.env.FG_ENV || '').trim().toLowerCase();
  return nodeEnv === 'production' || PROD_LIKE_FG_ENVS.has(fgEnv);
}

function resolutionError(
  resolution: Exclude<TenantRequestAuthorityResolution, { ok: true }>,
): TenantCredentialResolution {
  return resolution;
}

async function validateConfiguredOperatorAuthority(
  tenantId: string,
  requestId: string,
): Promise<OperatorAuthorityValidation> {
  if (!isProdLikeEnv()) return { ok: true };

  const now = Date.now();
  if (
    operatorAuthorityCache?.tenantId === tenantId &&
    operatorAuthorityCache.expiresAt > now
  ) {
    return operatorAuthorityCache.result;
  }

  const gatewaySecret = internalGatewaySecret();
  if (!gatewaySecret) {
    return {
      ok: false,
      status: 503,
      code: 'OPERATOR_TENANT_VALIDATION_UNAVAILABLE',
      message: 'Configured operator authority cannot be validated.',
    };
  }

  let result: OperatorAuthorityValidation;
  try {
    const response = await fetch(
      `${CORE_API_URL}/admin/tenants/${encodeURIComponent(tenantId)}/operator-authority`,
      {
        method: 'GET',
        cache: 'no-store',
        headers: {
          'X-API-Key': gatewaySecret,
          'X-FG-Internal-Token': gatewaySecret,
          'X-Admin-Gateway-Internal': 'true',
          'X-Request-ID': requestId,
        },
      },
    );
    if (response.ok) {
      const payload = await response.json().catch(() => null) as {
        tenant_kind?: string;
        lifecycle_state?: string;
        operator_authority_allowed?: boolean;
      } | null;
      result =
        payload?.tenant_kind === 'internal_platform' &&
        payload?.lifecycle_state === 'active' &&
        payload?.operator_authority_allowed === true
          ? { ok: true }
          : {
              ok: false,
              status: 403,
              code: 'OPERATOR_TENANT_NOT_ALLOWED',
              message: 'Configured tenant is not authorized for operator use.',
            };
    } else if (response.status === 404) {
      result = {
        ok: false,
        status: 404,
        code: 'TENANT_NOT_FOUND',
        message: 'Configured operator tenant was not found.',
      };
    } else if (response.status === 401 || response.status === 403) {
      result = {
        ok: false,
        status: 403,
        code: 'OPERATOR_TENANT_NOT_ALLOWED',
        message: 'Configured tenant is not authorized for operator use.',
      };
    } else {
      result = {
        ok: false,
        status: 503,
        code: 'OPERATOR_TENANT_VALIDATION_UNAVAILABLE',
        message: 'Configured operator authority cannot be validated.',
      };
    }
  } catch {
    result = {
      ok: false,
      status: 503,
      code: 'CORE_UNAVAILABLE',
      message: 'Core is unavailable for operator authority validation.',
    };
  }

  operatorAuthorityCache = {
    tenantId,
    result,
    expiresAt: now + OPERATOR_AUTHORITY_CACHE_MS,
  };
  return result;
}

/**
 * Resolve a Console human request to a tenant-bound Core credential.
 *
 * The configured operator credential is selected only when the shared
 * authority resolver classifies the caller as internal_console and explicitly
 * returns operatorFallback. Client-human sessions always use their canonical
 * session tenant and that tenant's credential.
 */
export async function resolveTenantCredentialForConsoleRequest(
  session: unknown,
  queryTenantIds: string[],
): Promise<TenantCredentialResolution> {
  const authority = resolveTenantRequestAuthority(session, {
    queryTenantIds,
    pathTenantId: null,
    allowOperatorFallback: true,
  });
  if (!authority.ok) return resolutionError(authority);

  if (authority.operatorFallback) {
    const tenantId = (process.env.CORE_TENANT_ID || '').trim();
    const apiKey = process.env.FG_CORE_API_KEY ?? process.env.CORE_API_KEY ?? '';
    if (
      !tenantId ||
      !TENANT_ID_RE.test(tenantId) ||
      (isProdLikeEnv() && tenantId.toLowerCase() === 'default')
    ) {
      return {
        ok: false,
        status: 503,
        code: 'TENANT_CONTEXT_INVALID',
        message: 'Configured operator tenant is missing or invalid.',
      };
    }
    if (!apiKey) {
      return {
        ok: false,
        status: 503,
        code: 'CORE_AUTH_MISSING',
        message: 'Configured operator credential is unavailable.',
      };
    }
    const operatorAuthority = await validateConfiguredOperatorAuthority(
      tenantId,
      crypto.randomUUID(),
    );
    if (!operatorAuthority.ok) return operatorAuthority;
    return {
      ok: true,
      tenantId,
      apiKey,
      authority: authority.authority,
      source: authority.source,
    };
  }

  const tenantId = authority.tenantId as string;
  const credential = await getTenantApiKey(tenantId);
  if (!credential.key) {
    return {
      ok: false,
      status: credential.unavailable ? 503 : 401,
      code: credential.unavailable
        ? 'CREDENTIAL_PERSISTENCE_UNAVAILABLE'
        : 'CORE_AUTH_MISSING',
      message: credential.unavailable
        ? 'Tenant credential persistence is unavailable.'
        : 'Tenant credential is unavailable.',
    };
  }

  return {
    ok: true,
    tenantId,
    apiKey: credential.key,
    authority: authority.authority,
    source: authority.source,
  };
}
