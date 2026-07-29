import { internalGatewaySecret } from './internal-gateway-secret';

const TENANT_ID_RE = /^[a-zA-Z0-9_-]{1,128}$/;
const PROD_LIKE_ENVS = new Set(['production', 'prod', 'staging']);

export function isProdLike(): boolean {
  const nodeEnv = (process.env.NODE_ENV || '').trim().toLowerCase();
  const fgEnv = (process.env.FG_ENV || '').trim().toLowerCase();
  return nodeEnv === 'production' || PROD_LIKE_ENVS.has(fgEnv);
}

/**
 * Validates all required production configuration at startup.
 *
 * Collects every problem and throws a single consolidated error so operators
 * see the full list at once rather than fixing one variable, redeploying, and
 * discovering the next gap.
 *
 * Only throws in prod-like environments (production / prod / staging).
 */
export function validateProductionConfig(): void {
  if (!isProdLike()) return;

  const errors: string[] = [];

  const coreApiUrl = (process.env.CORE_API_URL || '').trim();
  if (!coreApiUrl) {
    errors.push('  CORE_API_URL is not configured.');
  }

  const coreTenantId = (process.env.CORE_TENANT_ID || '').trim();
  if (!coreTenantId) {
    errors.push('  CORE_TENANT_ID is not configured.');
  } else if (coreTenantId.toLowerCase() === 'default') {
    errors.push('  CORE_TENANT_ID resolves to legacy value "default".');
  } else if (!TENANT_ID_RE.test(coreTenantId)) {
    errors.push(`  CORE_TENANT_ID "${coreTenantId}" is not a valid tenant ID.`);
  }

  if (!internalGatewaySecret()) {
    errors.push(
      '  Internal gateway secret is not configured (set FG_INTERNAL_GATEWAY_SECRET).',
    );
  }

  if (errors.length > 0) {
    throw new Error(
      'Production configuration invalid:\n' + errors.join('\n') + '\nConsole startup aborted.',
    );
  }
}
