/**
 * Evidence Explorer API client — Enterprise Evidence Explorer UI (PR 92)
 *
 * All requests proxy through /api/core → admin-gateway → fg-core.
 * The BFF adds X-API-Key and X-Tenant-ID server-side; no secrets ever touch
 * the browser. All functions return SafeResult<T> — never throw to callers.
 *
 * Security invariants:
 *  - No tenant_id from browser URL/body — resolved server-side by BFF.
 *  - No raw evidence bodies, prompts, vectors, provider payloads, or secrets.
 *  - evidence_source_metadata: only SAFE_SOURCE_META_KEYS extracted; never dump raw.
 *  - 403 = no tenant context; UI must render safe empty state.
 *  - 404 = not found or cross-tenant isolation; UI must not disclose.
 *  - Trust states are explicit: valid|invalid|missing|stale|unknown|unverifiable|restricted.
 *  - No client-side provenance authority — all governance decisions are server-side.
 */

const BFF = '/api/core';

// ---------------------------------------------------------------------------
// SafeResult — never throws to callers
// ---------------------------------------------------------------------------

export type SafeResult<T> =
  | { ok: true; data: T }
  | { ok: false; error: string; status?: number };

async function safeGet<T>(url: string): Promise<SafeResult<T>> {
  try {
    const resp = await fetch(url, { cache: 'no-store' });
    if (!resp.ok) {
      let detail = `HTTP ${resp.status}`;
      try {
        const body = await resp.json();
        if (body?.detail?.message) detail = body.detail.message;
        else if (typeof body?.detail === 'string') detail = body.detail;
      } catch {
        /* ignore parse errors */
      }
      return { ok: false, error: detail, status: resp.status };
    }
    const data: T = await resp.json();
    return { ok: true, data };
  } catch {
    return { ok: false, error: 'Network error — core unreachable' };
  }
}

// ---------------------------------------------------------------------------
// Trust state
// Explicit: never collapse unknown into valid, restricted into invalid, etc.
// ---------------------------------------------------------------------------

export type TrustState =
  | 'valid'
  | 'invalid'
  | 'missing'
  | 'stale'
  | 'unknown'
  | 'unverifiable'
  | 'restricted';

/**
 * Safe keys extracted from evidence_source_metadata for display.
 * Never dump the full dict; these keys are export-safe governance summaries.
 */
export const SAFE_SOURCE_META_KEYS = [
  'source_type',
  'source_system',
  'source_version',
  'schema_version',
  'ingestion_method',
  'extraction_version',
  'evidence_format',
  'source_category',
  'validation_status',
  'validation_reason',
  'integrity_verified',
  'hash_algorithm',
  'hash_verified',
  'chain_of_custody_ready',
  'export_safe',
] as const;

export type SafeSourceMetaKey = (typeof SAFE_SOURCE_META_KEYS)[number];

export function extractSafeSourceMeta(
  raw: Record<string, unknown>,
): Partial<Record<SafeSourceMetaKey, string>> {
  const result: Partial<Record<SafeSourceMetaKey, string>> = {};
  for (const key of SAFE_SOURCE_META_KEYS) {
    const v = raw[key];
    if (v !== null && v !== undefined) {
      result[key] = String(v);
    }
  }
  return result;
}

export function deriveTrustState(safeMeta: Partial<Record<SafeSourceMetaKey, string>>): TrustState {
  const vs = safeMeta['validation_status'];
  if (!vs) return 'unknown';
  const map: Record<string, TrustState> = {
    valid: 'valid',
    invalid: 'invalid',
    missing: 'missing',
    stale: 'stale',
    unverifiable: 'unverifiable',
    restricted: 'restricted',
  };
  return map[vs] ?? 'unknown';
}

// ---------------------------------------------------------------------------
// Evidence lifecycle states
// ---------------------------------------------------------------------------

export type EvidenceLifecycleState =
  | 'draft'
  | 'collected'
  | 'validated'
  | 'rejected'
  | 'superseded'
  | 'expired'
  | 'archived'
  | 'restricted'
  | 'unknown';

// ---------------------------------------------------------------------------
// Evidence types
// ---------------------------------------------------------------------------

export interface EvidenceReference {
  evidence_id: string;
  assessment_id: string;
  evidence_type: string;
  evidence_title: string;
  submitted_by: string;
  submitted_at: string;
  tenant_id: string;
  // Raw metadata intentionally typed as opaque — use extractSafeSourceMeta() for display.
  evidence_source_metadata: Record<string, unknown>;
  evidence_classification: string | null;
  control_ids: string[];
  notes: string | null;
}

// ---------------------------------------------------------------------------
// Audit dashboard types
// ---------------------------------------------------------------------------

export interface AuditOverview {
  current_invariant_status: string;
  drift_status: string;
  last_reproducibility_test: unknown | null;
  policy_hash: string | null;
  config_hash: string | null;
}

export interface AuditStatus {
  records: number;
  failed_records: number;
}

export interface AuditChainIntegrity {
  audit_chain_integrity: 'ok' | 'broken' | string;
}

// ---------------------------------------------------------------------------
// Investigation filter state
// ---------------------------------------------------------------------------

export interface EvidenceFilterState {
  evidenceType: string;
  classification: string;
  trustState: string;
  hasControls: boolean | null;
  sortOrder: 'asc' | 'desc';
}

export const DEFAULT_FILTERS: EvidenceFilterState = {
  evidenceType: '',
  classification: '',
  trustState: '',
  hasControls: null,
  sortOrder: 'desc',
};

// ---------------------------------------------------------------------------
// API functions
// ---------------------------------------------------------------------------

export async function listEvidence(
  assessmentId: string,
  limit = 50,
  offset = 0,
): Promise<SafeResult<EvidenceReference[]>> {
  return safeGet<EvidenceReference[]>(
    `${BFF}/control-plane/readiness/assessments/${assessmentId}/evidence?limit=${limit}&offset=${offset}`,
  );
}

export async function getAuditOverview(): Promise<SafeResult<AuditOverview>> {
  return safeGet<AuditOverview>(`${BFF}/ui/audit/overview`);
}

export async function getAuditStatus(): Promise<SafeResult<AuditStatus>> {
  return safeGet<AuditStatus>(`${BFF}/ui/audit/status`);
}

export async function getAuditChainIntegrity(): Promise<SafeResult<AuditChainIntegrity>> {
  return safeGet<AuditChainIntegrity>(`${BFF}/ui/audit/chain-integrity`);
}

// ---------------------------------------------------------------------------
// Client-side filtering and sorting (presentational only)
// All authoritative trust/governance decisions remain server-side.
// ---------------------------------------------------------------------------

export function applyEvidenceFilters(
  items: EvidenceReference[],
  filters: EvidenceFilterState,
): EvidenceReference[] {
  let out = items;
  if (filters.evidenceType) {
    out = out.filter((e) => e.evidence_type === filters.evidenceType);
  }
  if (filters.classification) {
    out = out.filter((e) => e.evidence_classification === filters.classification);
  }
  if (filters.trustState) {
    out = out.filter((e) => {
      const safe = extractSafeSourceMeta(e.evidence_source_metadata);
      return deriveTrustState(safe) === filters.trustState;
    });
  }
  if (filters.hasControls !== null) {
    out = out.filter((e) =>
      filters.hasControls ? e.control_ids.length > 0 : e.control_ids.length === 0,
    );
  }
  // Deterministic sort: primary=submitted_at, tiebreak=evidence_id
  out = [...out].sort((a, b) => {
    const diff =
      filters.sortOrder === 'desc'
        ? b.submitted_at.localeCompare(a.submitted_at)
        : a.submitted_at.localeCompare(b.submitted_at);
    return diff !== 0 ? diff : a.evidence_id.localeCompare(b.evidence_id);
  });
  return out;
}

export function collectFilterOptions(items: EvidenceReference[]) {
  const evidenceTypes = [...new Set(items.map((e) => e.evidence_type))].sort();
  const classifications = [
    ...new Set(items.map((e) => e.evidence_classification).filter(Boolean)),
  ].sort() as string[];
  return { evidenceTypes, classifications };
}

// ---------------------------------------------------------------------------
// Future seams — type stubs only, no API routes wired yet.
// ---------------------------------------------------------------------------

// Gap A — Export package generation
// Wire to future POST /control-plane/readiness/assessments/{id}/evidence-bundle
export interface EvidenceBundleManifest {
  bundle_id: string;
  assessment_id: string;
  evidence_count: number;
  chain_of_custody_verified: boolean;
  export_safe: boolean;
  created_at: string;
  expires_at: string | null;
}
// export async function generateEvidenceBundle(assessmentId: string): Promise<SafeResult<EvidenceBundleManifest>>

// Gap B — Legal / forensic review workflow
// DOM seam: aria-label="legal-review-panel" reserved in evidence explorer page.
export interface LegalReviewContext {
  review_id: string;
  evidence_ids: string[];
  review_state: string; // pending | in_review | approved | rejected | on_hold
  hold_reason: string | null;
  reviewer_assignments: string[];
  regulator_reference: string | null;
}
// export async function getLegalReviewContext(assessmentId: string): Promise<SafeResult<LegalReviewContext>>

// Gap C — Signed evidence verification
// DOM seam: aria-label="signed-evidence-panel" reserved.
export interface SignedEvidenceVerification {
  evidence_id: string;
  signature_valid: boolean;
  signer_id: string | null;
  signing_algorithm: string | null;
  signed_at: string | null;
  verification_timestamp: string;
}
// export async function verifySignedEvidence(evidenceId: string): Promise<SafeResult<SignedEvidenceVerification>>

// Gap D — Forensic timeline replay
// DOM seam: aria-label="forensic-replay-panel" reserved.
export interface ForensicReplayManifest {
  replay_id: string;
  assessment_id: string;
  evidence_snapshot_version: string;
  provenance_validation_version: string;
  replay_state: string; // pending | replaying | complete | failed
  determinism_verified: boolean;
  started_at: string;
  completed_at: string | null;
}
// export async function initiateForensicReplay(assessmentId: string): Promise<SafeResult<ForensicReplayManifest>>
