/**
 * FG-849-REPAIR-001 — Console Core BFF rate-limit policy authority.
 *
 * This module is the single authority for two decisions the BFF route makes
 * before any Core request:
 *
 *   1. Route risk classification. Every PROXY_RULES (prefix, method) pair in
 *      app/api/core/[...path]/route.ts has an explicit tier here, plus the two
 *      branches that never reach PROXY_RULES (public invitation preflight and
 *      the alignment artifact). tests/bff-rate-limit-route-policy.test.js
 *      fails when the two registries drift. Unknown routes, unknown methods and
 *      malformed path segments are UNCLASSIFIED and the route denies them.
 *
 *   2. Limiter identity. Quota partitions are derived with a server-only HMAC
 *      key from the authenticated session subject and the server-resolved
 *      tenant. No request header, query parameter or body field contributes
 *      to the partition. Keys and diagnostics carry only the opaque partition,
 *      never a raw subject, tenant id, invitation token or client IP.
 *
 * Failure policy: every tier fails closed (503) when enforcement is
 * unavailable. No tier has a fail-open exception — no compensating control
 * has been verified that would justify one. The Console's own liveness
 * endpoint (/api/health) is not routed through the limiter and keeps
 * reporting limiter health during an outage.
 *
 * Server-only: uses node:crypto and process.env; never import from client code.
 */

import { createHmac, hkdfSync, randomBytes } from 'crypto';

export const BFF_RATE_LIMIT_POLICY_VERSION = 'fg-849.v1';

/**
 * R0 — health; R1 — authenticated read; R2 — expensive or sensitive
 * operation; R3 — privileged mutation, credential or enrollment operation.
 */
export type BffRiskTier = 'R0' | 'R1' | 'R2' | 'R3';
export type BffFailureMode = 'deny';
type HttpMethod = 'GET' | 'HEAD' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';

/** Behaviour when the limiter cannot make a decision. Deny for every tier. */
export const TIER_FAILURE_MODE: Readonly<Record<BffRiskTier, BffFailureMode>> = Object.freeze({
  R0: 'deny',
  R1: 'deny',
  R2: 'deny',
  R3: 'deny',
});

export interface BffRouteFamily {
  /** Stable identifier used in audit events. */
  id: string;
  /** Must equal a PROXY_RULES prefix in the Core BFF route. */
  prefix: string;
  /** Exactly the methods PROXY_RULES admits for this prefix. */
  tiers: Readonly<Partial<Record<HttpMethod, BffRiskTier>>>;
}

const RO = (tier: BffRiskTier): { GET: BffRiskTier; HEAD: BffRiskTier } => ({ GET: tier, HEAD: tier });

const ROUTE_FAMILY_TABLE: BffRouteFamily[] = [
  // Invitation acceptance is enrollment. GET identity/invitations/{token} is
  // the public preflight and is additionally handled by the special policy.
  { id: 'identity.invitations', prefix: 'identity/invitations', tiers: { GET: 'R3', POST: 'R3' } },
  { id: 'health.live', prefix: 'health/live', tiers: RO('R0') },
  { id: 'health.ready', prefix: 'health/ready', tiers: RO('R0') },
  { id: 'stats.summary', prefix: 'stats/summary', tiers: RO('R1') },
  { id: 'feed.live', prefix: 'feed/live', tiers: RO('R1') },
  { id: 'decisions', prefix: 'decisions', tiers: RO('R1') },
  { id: 'forensics.chain.verify', prefix: 'forensics/chain/verify', tiers: RO('R2') },
  { id: 'forensics.snapshot', prefix: 'forensics/snapshot', tiers: RO('R2') },
  { id: 'forensics.audit_trail', prefix: 'forensics/audit_trail', tiers: RO('R2') },
  { id: 'keys', prefix: 'keys', tiers: { ...RO('R2'), POST: 'R3', DELETE: 'R3' } },
  { id: 'control-tower.snapshot', prefix: 'control-tower/snapshot', tiers: RO('R1') },
  { id: 'admin.connectors.status', prefix: 'admin/connectors/status', tiers: RO('R1') },
  { id: 'admin.connectors', prefix: 'admin/connectors', tiers: { ...RO('R1'), POST: 'R3' } },
  { id: 'admin.agent.devices', prefix: 'admin/agent/devices', tiers: RO('R1') },
  { id: 'admin.agent.quarantine', prefix: 'admin/agent/quarantine', tiers: { POST: 'R3' } },
  { id: 'admin.agent.unquarantine', prefix: 'admin/agent/unquarantine', tiers: { POST: 'R3' } },
  { id: 'control-plane.lockers', prefix: 'control-plane/lockers', tiers: { ...RO('R1'), POST: 'R3' } },
  { id: 'audit.export', prefix: 'audit/export', tiers: RO('R2') },
  { id: 'ingest.assessment', prefix: 'ingest/assessment', tiers: { ...RO('R1'), POST: 'R2', PATCH: 'R2' } },
  { id: 'ui.ai.chat', prefix: 'ui/ai/chat', tiers: { POST: 'R2' } },
  { id: 'rag.retrieval-policy', prefix: 'rag/retrieval-policy', tiers: { ...RO('R1'), PUT: 'R3' } },
  { id: 'rag.corpora', prefix: 'rag/corpora', tiers: RO('R1') },
  { id: 'rag.documents', prefix: 'rag/documents', tiers: { ...RO('R1'), POST: 'R2' } },
  { id: 'rag.upload', prefix: 'rag/upload', tiers: { POST: 'R2' } },
  { id: 'rag.uploads', prefix: 'rag/uploads', tiers: RO('R1') },
  { id: 'ui.forensics.events', prefix: 'ui/forensics/events', tiers: RO('R2') },
  { id: 'ui.forensics.trace', prefix: 'ui/forensics/trace', tiers: RO('R2') },
  { id: 'ui.provider.governance', prefix: 'ui/provider/governance', tiers: RO('R1') },
  { id: 'ui.provider.routing', prefix: 'ui/provider/routing', tiers: RO('R1') },
  { id: 'ui.provider.failover', prefix: 'ui/provider/failover', tiers: RO('R1') },
  { id: 'ui.evaluation.runs', prefix: 'ui/evaluation/runs', tiers: RO('R1') },
  { id: 'ui.evaluation.quality', prefix: 'ui/evaluation/quality', tiers: RO('R1') },
  { id: 'readiness.frameworks', prefix: 'control-plane/readiness/frameworks', tiers: RO('R1') },
  { id: 'readiness.assessments', prefix: 'control-plane/readiness/assessments', tiers: RO('R1') },
  { id: 'readiness.domains', prefix: 'control-plane/readiness/domains', tiers: RO('R1') },
  { id: 'readiness.controls', prefix: 'control-plane/readiness/controls', tiers: RO('R1') },
  { id: 'readiness.maturity-tiers', prefix: 'control-plane/readiness/maturity-tiers', tiers: RO('R1') },
  { id: 'ui.audit.overview', prefix: 'ui/audit/overview', tiers: RO('R1') },
  { id: 'ui.audit.status', prefix: 'ui/audit/status', tiers: RO('R1') },
  { id: 'ui.audit.chain-integrity', prefix: 'ui/audit/chain-integrity', tiers: RO('R1') },
  {
    id: 'field-assessment.engagements',
    prefix: 'field-assessment/engagements',
    tiers: { ...RO('R1'), POST: 'R3', PATCH: 'R3', DELETE: 'R3' },
  },
  { id: 'governance.graph', prefix: 'governance/graph', tiers: { ...RO('R1'), POST: 'R3' } },
  { id: 'governance.assets', prefix: 'governance/assets', tiers: RO('R1') },
  { id: 'workforce.users', prefix: 'workforce/users', tiers: { ...RO('R1'), POST: 'R3', PATCH: 'R3' } },
  { id: 'portal.grants', prefix: 'portal/grants', tiers: { ...RO('R1'), POST: 'R3', DELETE: 'R3' } },
  { id: 'admin.identity.tenants', prefix: 'admin/identity/tenants', tiers: { ...RO('R1'), POST: 'R3', PUT: 'R3' } },
  { id: 'admin.identity.invitations', prefix: 'admin/identity/invitations', tiers: { ...RO('R1'), POST: 'R3' } },
  {
    id: 'admin.tenants',
    prefix: 'admin/tenants',
    tiers: { ...RO('R1'), POST: 'R3', PATCH: 'R3', DELETE: 'R3' },
  },
  { id: 'api.executive', prefix: 'api/executive', tiers: RO('R1') },
  { id: 'admin.msp.relationships', prefix: 'admin/msp/relationships', tiers: { GET: 'R1', POST: 'R3' } },
  { id: 'admin.msp.customers', prefix: 'admin/msp/customers', tiers: { GET: 'R1', POST: 'R3' } },
  { id: 'admin.msp.portfolio', prefix: 'admin/msp/portfolio', tiers: { GET: 'R1' } },
  { id: 'admin.msp.assessments', prefix: 'admin/msp/assessments', tiers: { GET: 'R1', POST: 'R3' } },
  { id: 'admin.msp.onboarding', prefix: 'admin/msp/onboarding', tiers: { GET: 'R1', POST: 'R3' } },
  { id: 'admin.msp.report-shares', prefix: 'admin/msp/report-shares', tiers: { GET: 'R1', POST: 'R3' } },
  { id: 'admin.msp.reports', prefix: 'admin/msp/reports', tiers: { GET: 'R2' } },
];

export const BFF_ROUTE_FAMILIES: ReadonlyArray<BffRouteFamily> = Object.freeze(ROUTE_FAMILY_TABLE);

/**
 * Sub-actions that raise the tier above the family default wherever they
 * appear after the family prefix. A report export can never inherit the
 * read tier of its parent collection.
 */
const READ_ESCALATION_SEGMENTS: ReadonlySet<string> = new Set([
  'export',
  'exports',
  'download',
  'verify',
  'verification',
  'verification-bundle',
  'manifest',
]);
const MUTATION_ESCALATION_SEGMENTS: ReadonlySet<string> = new Set([
  'accept',
  'approve',
  'bootstrap-admin',
  'credential-administration',
  'export',
  'generate',
  'invite-initial-admin',
  'qa-approve',
  'quarantine',
  'release',
  'request-resend',
  'revoke',
  'rotate',
  'unquarantine',
  'verify',
]);

const TIER_RANK: Readonly<Record<BffRiskTier, number>> = { R0: 0, R1: 1, R2: 2, R3: 3 };
function maxTier(a: BffRiskTier, b: BffRiskTier): BffRiskTier {
  return TIER_RANK[a] >= TIER_RANK[b] ? a : b;
}

export type BffRouteClassification =
  | {
      ok: true;
      familyId: string;
      method: string;
      tier: BffRiskTier;
      failureMode: BffFailureMode;
      /** true only for the unauthenticated invitation preflight. */
      publicEndpoint: boolean;
    }
  | { ok: false; reason: 'UNCLASSIFIED_ROUTE' | 'UNCLASSIFIED_METHOD' | 'MALFORMED_PATH' };

/**
 * A segment that could change the upstream path after URL normalisation, or
 * smuggle a separator, is never classified.
 */
function isSafeSegment(segment: unknown): segment is string {
  if (typeof segment !== 'string' || segment.length === 0 || segment.length > 512) return false;
  if (segment === '.' || segment === '..') return false;
  if (segment.includes('/') || segment.includes('\\')) return false;
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001f\u007f]/.test(segment)) return false;
  return true;
}

function findFamily(joined: string): BffRouteFamily | null {
  let best: BffRouteFamily | null = null;
  for (const family of BFF_ROUTE_FAMILIES) {
    if (joined === family.prefix || joined.startsWith(`${family.prefix}/`)) {
      if (!best || family.prefix.length > best.prefix.length) best = family;
    }
  }
  return best;
}

export function isInvitationPreflightRoute(path: ReadonlyArray<string>, method: string): boolean {
  return method === 'GET' && path.length === 3 && path[0] === 'identity' && path[1] === 'invitations';
}

export function isAlignmentArtifactRoute(path: ReadonlyArray<string>, method: string): boolean {
  return method === 'GET' && path.length === 1 && path[0] === 'alignment-artifact';
}

/** Deterministic, deny-by-default classification of a BFF request. */
export function classifyBffRoute(path: ReadonlyArray<string>, rawMethod: string): BffRouteClassification {
  const method = String(rawMethod || '').toUpperCase();
  if (!Array.isArray(path) || path.length === 0) return { ok: false, reason: 'UNCLASSIFIED_ROUTE' };
  if (!path.every(isSafeSegment)) return { ok: false, reason: 'MALFORMED_PATH' };

  if (isInvitationPreflightRoute(path, method)) {
    return { ok: true, familyId: 'identity.invitations.preflight', method, tier: 'R3', failureMode: 'deny', publicEndpoint: true };
  }
  if (path[0] === 'alignment-artifact') {
    if (!isAlignmentArtifactRoute(path, method)) {
      return { ok: false, reason: path.length === 1 ? 'UNCLASSIFIED_METHOD' : 'UNCLASSIFIED_ROUTE' };
    }
    return { ok: true, familyId: 'alignment-artifact', method, tier: 'R1', failureMode: 'deny', publicEndpoint: false };
  }

  const family = findFamily(path.join('/'));
  if (!family) return { ok: false, reason: 'UNCLASSIFIED_ROUTE' };
  const baseTier = family.tiers[method as HttpMethod];
  if (!baseTier) return { ok: false, reason: 'UNCLASSIFIED_METHOD' };

  const isRead = method === 'GET' || method === 'HEAD';
  const escalation = isRead ? READ_ESCALATION_SEGMENTS : MUTATION_ESCALATION_SEGMENTS;
  const prefixLength = family.prefix.split('/').length;
  let tier = baseTier;
  for (const segment of path.slice(prefixLength)) {
    if (escalation.has(segment.toLowerCase())) tier = maxTier(tier, isRead ? 'R2' : 'R3');
  }
  return { ok: true, familyId: family.id, method, tier, failureMode: TIER_FAILURE_MODE[tier], publicEndpoint: false };
}

// ─── Public invitation preflight ─────────────────────────────────────────────

/** fgwi1.* workforce invitation token: prefix + 32-byte hex (api/identity/workforce_token.py). */
const INVITATION_TOKEN_RE = /^fgwi1\.[0-9a-f]{64}$/;

export function isWellFormedInvitationToken(token: unknown): boolean {
  return typeof token === 'string' && INVITATION_TOKEN_RE.test(token);
}

function boundedInt(raw: string | undefined, fallback: number): number {
  const parsed = parseInt(raw || '', 10);
  return Number.isFinite(parsed) && parsed >= 1 ? parsed : fallback;
}

/**
 * Public preflight has no authenticated session and no verifiably trusted
 * client-IP header (x-forwarded-for / x-real-ip are caller-controlled unless
 * an edge is proven to overwrite them). It is therefore bounded by:
 *   - a deployment-wide budget shared by all callers, and
 *   - a per-token budget keyed by the HMAC of the token.
 * Both are enforced in the shared store; neither is per-instance.
 */
export function getPublicInvitationRateLimitConfig(): { globalMaxRequests: number; perTokenMaxRequests: number } {
  return {
    globalMaxRequests: boundedInt(process.env.BFF_RATE_LIMIT_PUBLIC_INVITATION_MAX_REQUESTS, 120),
    perTokenMaxRequests: boundedInt(process.env.BFF_RATE_LIMIT_PUBLIC_INVITATION_TOKEN_MAX_REQUESTS, 10),
  };
}

// ─── Limiter identity key material ───────────────────────────────────────────

const PROD_LIKE_FG_ENVS = new Set(['prod', 'production', 'staging']);
/** AUTH_SECRET fallback minimum (the documented `openssl rand -base64 32` is 44 chars). */
const MIN_SECRET_LENGTH = 32;
/**
 * Dedicated secret minimum: 43 characters is the shortest supported encoding
 * of 32 random bytes (unpadded base64; padded base64 is 44, hex is 64).
 * Entropy itself cannot be measured — generate with `openssl rand -base64 32`.
 */
const MIN_DEDICATED_SECRET_LENGTH = 43;
const HKDF_SALT = 'frostgate-console-bff';
const HKDF_INFO = 'fg-849/rate-limit-identity/v1';

function isProdLike(): boolean {
  const nodeEnv = (process.env.NODE_ENV || '').trim().toLowerCase();
  const fgEnv = (process.env.FG_ENV || '').trim().toLowerCase();
  return nodeEnv === 'production' || PROD_LIKE_FG_ENVS.has(fgEnv);
}

function usableSecret(raw: string | undefined, minLength: number = MIN_SECRET_LENGTH): string | null {
  const value = (raw || '').trim();
  if (value.length < minLength) return null;
  if (value.toUpperCase().startsWith('CHANGE_ME')) return null;
  return value;
}

let ephemeralDevKey: Buffer | null = null;

export type LimiterKeyMaterial =
  | { ok: true; key: Buffer; source: 'dedicated' | 'derived-auth-secret' | 'ephemeral-dev' }
  | { ok: false; reason: 'BFF_RATE_LIMIT_KEY_UNAVAILABLE' };

/**
 * Resolve the HMAC key for limiter partitions.
 *
 *   1. BFF_RATE_LIMIT_KEY_SECRET (the planned production configuration; at
 *      least 43 characters, i.e. 32 random bytes encoded). If it is set but
 *      unusable the result is unavailable — a misconfigured dedicated secret
 *      never silently falls back.
 *   2. Emergency compatibility only: a domain-separated HKDF subkey of AUTH_SECRET (already a
 *      required server-only secret). The info label separates this purpose
 *      from session signing; the raw AUTH_SECRET is never used as the key.
 *   3. Dev/test only: a random per-process key.
 * Prod-like environments with no usable secret are unavailable (fail closed).
 *
 * Rotation: changing the secret starts a new key epoch; counters under the
 * old epoch simply expire within one window.
 */
export function resolveLimiterKeyMaterial(): LimiterKeyMaterial {
  const dedicatedRaw = process.env.BFF_RATE_LIMIT_KEY_SECRET;
  if (dedicatedRaw !== undefined && dedicatedRaw.trim() !== '') {
    const dedicated = usableSecret(dedicatedRaw, MIN_DEDICATED_SECRET_LENGTH);
    if (!dedicated) return { ok: false, reason: 'BFF_RATE_LIMIT_KEY_UNAVAILABLE' };
    return { ok: true, key: Buffer.from(hkdfSync('sha256', dedicated, HKDF_SALT, HKDF_INFO, 32)), source: 'dedicated' };
  }
  const authSecret = usableSecret(process.env.AUTH_SECRET);
  if (authSecret) {
    return { ok: true, key: Buffer.from(hkdfSync('sha256', authSecret, HKDF_SALT, HKDF_INFO, 32)), source: 'derived-auth-secret' };
  }
  if (isProdLike()) return { ok: false, reason: 'BFF_RATE_LIMIT_KEY_UNAVAILABLE' };
  if (!ephemeralDevKey) ephemeralDevKey = randomBytes(32);
  return { ok: true, key: ephemeralDevKey, source: 'ephemeral-dev' };
}

/**
 * Deterministic opaque partition id. Components are length-prefixed so no
 * two distinct component tuples can produce the same HMAC input.
 */
export function deriveRateLimitPartition(key: Buffer, components: ReadonlyArray<string>): string {
  const input = ['fg-849.v1', ...components].map((part) => `${part.length}:${part}`).join('|');
  return createHmac('sha256', key).update(input, 'utf8').digest('hex').slice(0, 32);
}

function safeGroup(routeGroup: string): string {
  return (routeGroup || 'unknown').replace(/[^a-zA-Z0-9_-]/g, '_').slice(0, 64);
}

export type RateLimitScope = 'tenant' | 'tenant-independent';

/** Key for an authenticated request: fg:bff:rl:v1:{route_group}:{opaque partition}. */
export function deriveAuthenticatedRateLimitKey(
  key: Buffer,
  routeGroup: string,
  scope: RateLimitScope,
  tenantId: string,
  principal: string,
): { key: string; partitionRef: string } {
  const partition = deriveRateLimitPartition(key, ['authenticated', scope, tenantId, principal]);
  return { key: `fg:bff:rl:v1:${safeGroup(routeGroup)}:${partition}`, partitionRef: partition.slice(0, 12) };
}

/**
 * Key namespace of the current key epoch. Every limiter key is derived under
 * the limiter secret, so deployments with different secrets (Production vs
 * Preview) never share a counter even when they share one Redis/Upstash
 * database, while all workers of one deployment (same secret) do.
 */
export function deriveRateLimitNamespace(key: Buffer): string {
  return deriveRateLimitPartition(key, ['namespace']).slice(0, 16);
}

export function derivePublicInvitationRateLimitKeys(
  key: Buffer,
  token: string,
): { globalKey: string; tokenKey: string; partitionRef: string } {
  const partition = deriveRateLimitPartition(key, ['public-invitation-token', token]);
  return {
    globalKey: `fg:bff:rl:v1:invitation-preflight:global:${deriveRateLimitNamespace(key)}`,
    tokenKey: `fg:bff:rl:v1:invitation-preflight:tok:${partition}`,
    partitionRef: partition.slice(0, 12),
  };
}
