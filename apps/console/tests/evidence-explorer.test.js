/**
 * evidence-explorer.test.js
 *
 * Static-analysis tests for PR 92 — Enterprise Evidence Explorer UI &
 * Provenance Investigation Console.
 *
 * Coverage:
 *   - File existence: all 8 components, API client, page, index
 *   - Barrel index exports all evidence components
 *   - evidenceApi.ts: SafeResult, TrustState, SAFE_SOURCE_META_KEYS, all types, API functions
 *   - evidenceApi.ts: applyEvidenceFilters, collectFilterOptions, deriveTrustState
 *   - evidenceApi.ts: future seam stubs (Gap A–D) with reserved aria-labels
 *   - BFF proxy: 3 audit routes present, GET/HEAD only, no write paths
 *   - InvestigationFilters: all 5 filter fields, clear filters, result count
 *   - EvidenceTimeline: bounded render (100), keyboard nav, aria-selected, trust icon
 *   - EvidenceDetailPanel: safe metadata extraction, hidden key count, export readiness
 *   - LinkedControlsPanel: no-controls warning, control list, authority note
 *   - AuditChainPanel: 3-endpoint fetch, chain integrity status, record counts
 *   - ProvenanceStatusPanel: trust state, degraded-state warnings, validation fields
 *   - ChainOfCustodyPanel: CoC readiness indicators, hash info
 *   - SnapshotReplayPanel: assessment anchor, forensic-replay seam comment
 *   - Page: 'use client', evidence components wired, filters wired, audit panel
 *   - Page: cancelled-flag cleanup, useEffect, listEvidence call
 *   - Security: no dangerouslySetInnerHTML in any evidence file
 *   - Security: no raw evidence_source_metadata dumped
 *   - Security: no tenant_id from browser in API client
 *   - Security: SAFE_SOURCE_META_KEYS allowlist enforced
 *   - Accessibility: aria-labels present, aria-hidden on decorative icons
 *   - TrustState: all 7 states covered, unknown never collapses to valid
 *   - Deterministic sort: primary by submitted_at, tiebreak by evidence_id
 */

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

function read(relPath) {
  return fs.readFileSync(path.join(__dirname, '..', relPath), 'utf8');
}

function exists(relPath) {
  return fs.existsSync(path.join(__dirname, '..', relPath));
}

// ─── File existence ────────────────────────────────────────────────────────────

test('all evidence explorer component files exist', () => {
  const files = [
    'lib/evidenceApi.ts',
    'components/evidence/AuditChainPanel.tsx',
    'components/evidence/ChainOfCustodyPanel.tsx',
    'components/evidence/EvidenceDetailPanel.tsx',
    'components/evidence/EvidenceTimeline.tsx',
    'components/evidence/InvestigationFilters.tsx',
    'components/evidence/LinkedControlsPanel.tsx',
    'components/evidence/ProvenanceStatusPanel.tsx',
    'components/evidence/SnapshotReplayPanel.tsx',
    'components/evidence/index.ts',
    'app/dashboard/provenance/page.tsx',
  ];
  for (const f of files) {
    assert.ok(exists(f), `Missing: ${f}`);
  }
});

test('evidence barrel index exports all components', () => {
  const idx = read('components/evidence/index.ts');
  const expected = [
    'AuditChainPanel',
    'ChainOfCustodyPanel',
    'EvidenceDetailPanel',
    'EvidenceTimeline',
    'InvestigationFilters',
    'LinkedControlsPanel',
    'ProvenanceStatusPanel',
    'SnapshotReplayPanel',
  ];
  for (const name of expected) {
    assert.match(idx, new RegExp(name), `barrel missing: ${name}`);
  }
});

// ─── evidenceApi.ts ────────────────────────────────────────────────────────────

test('evidenceApi uses BFF proxy prefix, not admin-gateway', () => {
  const api = read('lib/evidenceApi.ts');
  assert.match(api, /const BFF = '\/api\/core'/);
  assert.doesNotMatch(api, /CORE_API_URL/);
});

test('evidenceApi defines SafeResult type', () => {
  const api = read('lib/evidenceApi.ts');
  assert.match(api, /SafeResult<T>/);
  assert.match(api, /ok: true/);
  assert.match(api, /ok: false/);
});

test('evidenceApi defines all 7 TrustState values', () => {
  const api = read('lib/evidenceApi.ts');
  for (const state of ['valid', 'invalid', 'missing', 'stale', 'unknown', 'unverifiable', 'restricted']) {
    assert.match(api, new RegExp(`'${state}'`), `TrustState missing: ${state}`);
  }
});

test('evidenceApi SAFE_SOURCE_META_KEYS allowlist exists and has required keys', () => {
  const api = read('lib/evidenceApi.ts');
  assert.match(api, /SAFE_SOURCE_META_KEYS/);
  for (const key of ['validation_status', 'integrity_verified', 'chain_of_custody_ready', 'export_safe', 'hash_algorithm']) {
    assert.match(api, new RegExp(key), `SAFE_SOURCE_META_KEYS missing: ${key}`);
  }
});

test('evidenceApi extractSafeSourceMeta uses allowlist, does not dump raw', () => {
  const api = read('lib/evidenceApi.ts');
  assert.match(api, /extractSafeSourceMeta/);
  assert.match(api, /SAFE_SOURCE_META_KEYS/);
  assert.doesNotMatch(api, /JSON\.stringify.*evidence_source_metadata/);
});

test('evidenceApi deriveTrustState defaults to unknown, never collapses to valid', () => {
  const api = read('lib/evidenceApi.ts');
  assert.match(api, /deriveTrustState/);
  assert.match(api, /return 'unknown'/);
  assert.doesNotMatch(api, /\?\? 'valid'/);
});

test('evidenceApi defines EvidenceReference interface', () => {
  const api = read('lib/evidenceApi.ts');
  assert.match(api, /EvidenceReference/);
  assert.match(api, /evidence_id/);
  assert.match(api, /evidence_source_metadata/);
  assert.match(api, /control_ids/);
  assert.match(api, /submitted_at/);
});

test('evidenceApi defines EvidenceFilterState and DEFAULT_FILTERS', () => {
  const api = read('lib/evidenceApi.ts');
  assert.match(api, /EvidenceFilterState/);
  assert.match(api, /DEFAULT_FILTERS/);
  assert.match(api, /sortOrder/);
  assert.match(api, /hasControls/);
});

test('evidenceApi applyEvidenceFilters sorts with deterministic tiebreaker', () => {
  const api = read('lib/evidenceApi.ts');
  assert.match(api, /applyEvidenceFilters/);
  assert.match(api, /submitted_at/);
  assert.match(api, /evidence_id/);
  assert.match(api, /localeCompare/);
});

test('evidenceApi defines listEvidence API function', () => {
  const api = read('lib/evidenceApi.ts');
  assert.match(api, /listEvidence/);
  assert.match(api, /assessmentId/);
  assert.match(api, /SafeResult<EvidenceReference\[\]>/);
});

test('evidenceApi defines 3 audit API functions', () => {
  const api = read('lib/evidenceApi.ts');
  assert.match(api, /getAuditOverview/);
  assert.match(api, /getAuditStatus/);
  assert.match(api, /getAuditChainIntegrity/);
});

test('evidenceApi audit types have required fields', () => {
  const api = read('lib/evidenceApi.ts');
  assert.match(api, /AuditOverview/);
  assert.match(api, /current_invariant_status/);
  assert.match(api, /drift_status/);
  assert.match(api, /AuditChainIntegrity/);
  assert.match(api, /audit_chain_integrity/);
  assert.match(api, /AuditStatus/);
  assert.match(api, /failed_records/);
});

test('evidenceApi future seam stubs exist for all 4 gaps', () => {
  const api = read('lib/evidenceApi.ts');
  assert.match(api, /EvidenceBundleManifest/);
  assert.match(api, /LegalReviewContext/);
  assert.match(api, /SignedEvidenceVerification/);
  assert.match(api, /ForensicReplayManifest/);
});

test('evidenceApi Gap B seam reserves legal-review-panel aria-label', () => {
  const api = read('lib/evidenceApi.ts');
  assert.match(api, /legal-review-panel/);
});

test('evidenceApi Gap C seam reserves signed-evidence-panel aria-label', () => {
  const api = read('lib/evidenceApi.ts');
  assert.match(api, /signed-evidence-panel/);
});

test('evidenceApi Gap D seam reserves forensic-replay-panel aria-label', () => {
  const api = read('lib/evidenceApi.ts');
  assert.match(api, /forensic-replay-panel/);
});

// ─── BFF proxy routes ─────────────────────────────────────────────────────────

test('BFF proxy has all 3 UI audit routes for PR 92', () => {
  const route = read('app/api/core/[...path]/route.ts');
  assert.match(route, /ui\/audit\/overview/);
  assert.match(route, /ui\/audit\/status/);
  assert.match(route, /ui\/audit\/chain-integrity/);
});

test('UI audit proxy routes are GET/HEAD only — no write paths', () => {
  const route = read('app/api/core/[...path]/route.ts');
  const auditSection = route.slice(
    route.indexOf('ui/audit/overview'),
    route.indexOf('ui/audit/chain-integrity') + 80,
  );
  assert.doesNotMatch(auditSection, /POST|PUT|PATCH|DELETE/);
});

// ─── InvestigationFilters ─────────────────────────────────────────────────────

test('InvestigationFilters has all filter fields', () => {
  const c = read('components/evidence/InvestigationFilters.tsx');
  assert.match(c, /investigation-filters/);
  assert.match(c, /filter-evidence-type/);
  assert.match(c, /filter-classification/);
  assert.match(c, /filter-trust-state/);
  assert.match(c, /filter-has-controls/);
  assert.match(c, /filter-sort-order/);
});

test('InvestigationFilters shows clear button and result count', () => {
  const c = read('components/evidence/InvestigationFilters.tsx');
  assert.match(c, /Clear.*filter/i);
  assert.match(c, /filter-result-count/);
});

test('InvestigationFilters covers all 7 trust states', () => {
  const c = read('components/evidence/InvestigationFilters.tsx');
  for (const state of ['valid', 'invalid', 'missing', 'stale', 'unknown', 'unverifiable', 'restricted']) {
    assert.match(c, new RegExp(state), `trust state missing in filters: ${state}`);
  }
});

// ─── EvidenceTimeline ─────────────────────────────────────────────────────────

test('EvidenceTimeline enforces bounded render at 100 items', () => {
  const c = read('components/evidence/EvidenceTimeline.tsx');
  assert.match(c, /slice\(0, 100\)/);
  assert.match(c, /timeline-truncated/);
});

test('EvidenceTimeline has keyboard navigation and aria-selected', () => {
  const c = read('components/evidence/EvidenceTimeline.tsx');
  assert.match(c, /onKeyDown/);
  assert.match(c, /tabIndex={0}/);
  assert.match(c, /aria-selected/);
  assert.match(c, /role="option"/);
});

test('EvidenceTimeline uses time element with dateTime', () => {
  const c = read('components/evidence/EvidenceTimeline.tsx');
  assert.match(c, /<time/);
  assert.match(c, /dateTime/);
});

test('EvidenceTimeline shows text badge alongside icon (not color-only)', () => {
  const c = read('components/evidence/EvidenceTimeline.tsx');
  assert.match(c, /Badge.*variant/);
  assert.match(c, /trust/);
});

test('EvidenceTimeline has aria-label on card and per-item', () => {
  const c = read('components/evidence/EvidenceTimeline.tsx');
  assert.match(c, /evidence-timeline/);
  assert.match(c, /evidence-item-/);
});

// ─── EvidenceDetailPanel ──────────────────────────────────────────────────────

test('EvidenceDetailPanel uses extractSafeSourceMeta, not raw dump', () => {
  const c = read('components/evidence/EvidenceDetailPanel.tsx');
  assert.match(c, /extractSafeSourceMeta/);
  assert.doesNotMatch(c, /JSON\.stringify.*evidence_source_metadata/);
});

test('EvidenceDetailPanel shows hidden key count for transparency', () => {
  const c = read('components/evidence/EvidenceDetailPanel.tsx');
  assert.match(c, /hiddenKeyCount/);
  assert.match(c, /metadata-hidden-count/);
});

test('EvidenceDetailPanel shows export readiness indicators', () => {
  const c = read('components/evidence/EvidenceDetailPanel.tsx');
  assert.match(c, /export-readiness-indicators/);
  assert.match(c, /export_safe/);
  assert.match(c, /integrity_verified/);
  assert.match(c, /chain_of_custody_ready/);
});

test('EvidenceDetailPanel shows trust state badge', () => {
  const c = read('components/evidence/EvidenceDetailPanel.tsx');
  assert.match(c, /trust-state-badge/);
  assert.match(c, /trustVariant/);
});

// ─── LinkedControlsPanel ─────────────────────────────────────────────────────

test('LinkedControlsPanel warns when no controls linked', () => {
  const c = read('components/evidence/LinkedControlsPanel.tsx');
  assert.match(c, /no-controls-warning/);
  assert.match(c, /No controls linked/);
});

test('LinkedControlsPanel lists control IDs with aria-labels', () => {
  const c = read('components/evidence/LinkedControlsPanel.tsx');
  assert.match(c, /control-id-list/);
  assert.match(c, /linked-control-/);
  assert.match(c, /font-mono/);
});

test('LinkedControlsPanel has authority note about server-side linkage', () => {
  const c = read('components/evidence/LinkedControlsPanel.tsx');
  assert.match(c, /authoritative from the readiness API/);
  assert.match(c, /Do not infer control/);
});

// ─── AuditChainPanel ──────────────────────────────────────────────────────────

test('AuditChainPanel fetches from all 3 audit endpoints', () => {
  const c = read('components/evidence/AuditChainPanel.tsx');
  assert.match(c, /getAuditOverview/);
  assert.match(c, /getAuditStatus/);
  assert.match(c, /getAuditChainIntegrity/);
});

test('AuditChainPanel has cancelled-flag cleanup in useEffect', () => {
  const c = read('components/evidence/AuditChainPanel.tsx');
  assert.match(c, /cancelled = false/);
  assert.match(c, /cancelled = true/);
  assert.match(c, /if \(cancelled\)/);
});

test('AuditChainPanel shows chain integrity status and record counts', () => {
  const c = read('components/evidence/AuditChainPanel.tsx');
  assert.match(c, /audit-chain-integrity-status/);
  assert.match(c, /audit-record-counts/);
  assert.match(c, /failed_records/);
});

test('AuditChainPanel has loading and error aria-labels', () => {
  const c = read('components/evidence/AuditChainPanel.tsx');
  assert.match(c, /audit-chain-loading/);
  assert.match(c, /audit-chain-error/);
});

test('AuditChainPanel has authority note about server-side decisions', () => {
  const c = read('components/evidence/AuditChainPanel.tsx');
  assert.match(c, /authoritative from the ledger API/);
});

// ─── ProvenanceStatusPanel ────────────────────────────────────────────────────

test('ProvenanceStatusPanel derives trust state from safe metadata', () => {
  const c = read('components/evidence/ProvenanceStatusPanel.tsx');
  assert.match(c, /extractSafeSourceMeta/);
  assert.match(c, /deriveTrustState/);
  assert.match(c, /provenance-trust-state/);
});

test('ProvenanceStatusPanel shows degraded-state warnings for invalid/missing/stale', () => {
  const c = read('components/evidence/ProvenanceStatusPanel.tsx');
  assert.match(c, /provenance-warning/);
  assert.match(c, /invalid/);
  assert.match(c, /missing/);
  assert.match(c, /stale/);
});

test('ProvenanceStatusPanel shows integrity-verified field', () => {
  const c = read('components/evidence/ProvenanceStatusPanel.tsx');
  assert.match(c, /provenance-integrity-verified/);
  assert.match(c, /integrity_verified/);
});

// ─── ChainOfCustodyPanel ──────────────────────────────────────────────────────

test('ChainOfCustodyPanel shows readiness indicators for CoC, integrity, export', () => {
  const c = read('components/evidence/ChainOfCustodyPanel.tsx');
  assert.match(c, /chain-of-custody-panel/);
  assert.match(c, /coc-readiness-indicators/);
  assert.match(c, /chain_of_custody_ready/);
  assert.match(c, /integrity_verified/);
  assert.match(c, /export_safe/);
});

test('ChainOfCustodyPanel shows hash information', () => {
  const c = read('components/evidence/ChainOfCustodyPanel.tsx');
  assert.match(c, /coc-hash-info/);
  assert.match(c, /hash_algorithm/);
  assert.match(c, /hash_verified/);
});

test('ChainOfCustodyPanel has authority note about readiness vs legal certification', () => {
  const c = read('components/evidence/ChainOfCustodyPanel.tsx');
  assert.match(c, /authoritative from the evidence API/);
  assert.match(c, /does not constitute legal/);
});

// ─── SnapshotReplayPanel ──────────────────────────────────────────────────────

test('SnapshotReplayPanel shows assessment and evidence anchor fields', () => {
  const c = read('components/evidence/SnapshotReplayPanel.tsx');
  assert.match(c, /snapshot-replay-panel/);
  assert.match(c, /snapshot-anchor/);
  assert.match(c, /assessment_id|assessmentId/);
  assert.match(c, /evidence_id|evidence\.evidence_id/);
});

test('SnapshotReplayPanel has forensic-replay seam comment', () => {
  const c = read('components/evidence/SnapshotReplayPanel.tsx');
  assert.match(c, /forensic-replay/);
  assert.match(c, /forensic-replay-seam/);
});

test('SnapshotReplayPanel notes replay is authoritative from API, not client-side', () => {
  const c = read('components/evidence/SnapshotReplayPanel.tsx');
  assert.match(c, /authoritative from the forensic replay API/);
  assert.match(c, /not derived client-side/);
});

// ─── Page ─────────────────────────────────────────────────────────────────────

test('provenance page is a client component', () => {
  const page = read('app/dashboard/provenance/page.tsx');
  assert.match(page, /'use client'/);
});

test('provenance page wires all evidence components', () => {
  const page = read('app/dashboard/provenance/page.tsx');
  const components = [
    'AuditChainPanel',
    'EvidenceTimeline',
    'EvidenceDetailPanel',
    'ProvenanceStatusPanel',
    'LinkedControlsPanel',
    'ChainOfCustodyPanel',
    'SnapshotReplayPanel',
    'InvestigationFilters',
  ];
  for (const name of components) {
    assert.match(page, new RegExp(name), `page missing component: ${name}`);
  }
});

test('provenance page calls listEvidence', () => {
  const page = read('app/dashboard/provenance/page.tsx');
  assert.match(page, /listEvidence/);
});

test('provenance page paginates through all evidence pages until short page', () => {
  const page = read('app/dashboard/provenance/page.tsx');
  assert.match(page, /MAX_PAGES/);
  assert.match(page, /PAGE_SIZE/);
  assert.match(page, /result\.data\.length < PAGE_SIZE/);
  assert.match(page, /page \* PAGE_SIZE/);
});

test('provenance page has cancelled-flag cleanup in useEffect', () => {
  const page = read('app/dashboard/provenance/page.tsx');
  assert.match(page, /cancelled = false/);
  assert.match(page, /cancelled = true/);
});

test('provenance page applies filters and memoizes', () => {
  const page = read('app/dashboard/provenance/page.tsx');
  assert.match(page, /applyEvidenceFilters/);
  assert.match(page, /useMemo/);
  assert.match(page, /collectFilterOptions/);
});

test('provenance page has error and loading aria-labels', () => {
  const page = read('app/dashboard/provenance/page.tsx');
  assert.match(page, /evidence-fetch-error/);
  assert.match(page, /evidence-loading/);
});

test('provenance page has legal-review and signed-evidence seam comments', () => {
  const page = read('app/dashboard/provenance/page.tsx');
  assert.match(page, /legal-review-panel/);
  assert.match(page, /signed-evidence-panel/);
});

// ─── Security ─────────────────────────────────────────────────────────────────

test('no dangerouslySetInnerHTML in any evidence file', () => {
  const files = [
    'lib/evidenceApi.ts',
    'components/evidence/AuditChainPanel.tsx',
    'components/evidence/ChainOfCustodyPanel.tsx',
    'components/evidence/EvidenceDetailPanel.tsx',
    'components/evidence/EvidenceTimeline.tsx',
    'components/evidence/InvestigationFilters.tsx',
    'components/evidence/LinkedControlsPanel.tsx',
    'components/evidence/ProvenanceStatusPanel.tsx',
    'components/evidence/SnapshotReplayPanel.tsx',
    'app/dashboard/provenance/page.tsx',
  ];
  for (const f of files) {
    assert.doesNotMatch(read(f), /dangerouslySetInnerHTML/, `${f}: dangerouslySetInnerHTML forbidden`);
  }
});

test('evidenceApi does not accept tenant_id from client request body or URL params', () => {
  const api = read('lib/evidenceApi.ts');
  assert.match(api, /No tenant_id from browser/);
  assert.doesNotMatch(api, /searchParams.*tenant_id/);
  assert.doesNotMatch(api, /body.*tenant_id.*override/);
});

test('evidence components do not access raw evidence_source_metadata directly', () => {
  const files = [
    'components/evidence/EvidenceTimeline.tsx',
    'components/evidence/LinkedControlsPanel.tsx',
    'components/evidence/ProvenanceStatusPanel.tsx',
    'components/evidence/ChainOfCustodyPanel.tsx',
    'components/evidence/SnapshotReplayPanel.tsx',
  ];
  for (const f of files) {
    const content = read(f);
    assert.doesNotMatch(
      content,
      /evidence_source_metadata\[/,
      `${f}: direct metadata access forbidden — use extractSafeSourceMeta()`,
    );
  }
});

// ─── Accessibility ────────────────────────────────────────────────────────────

test('decorative icons have aria-hidden in evidence components', () => {
  const files = [
    'components/evidence/AuditChainPanel.tsx',
    'components/evidence/EvidenceTimeline.tsx',
    'components/evidence/LinkedControlsPanel.tsx',
  ];
  for (const f of files) {
    assert.match(read(f), /aria-hidden="true"/, `${f}: decorative icons need aria-hidden`);
  }
});

test('all evidence components have aria-label on root card', () => {
  const labels = [
    ['components/evidence/AuditChainPanel.tsx', 'audit-chain-panel'],
    ['components/evidence/ChainOfCustodyPanel.tsx', 'chain-of-custody-panel'],
    ['components/evidence/EvidenceDetailPanel.tsx', 'evidence-detail-panel'],
    ['components/evidence/EvidenceTimeline.tsx', 'evidence-timeline'],
    ['components/evidence/InvestigationFilters.tsx', 'investigation-filters'],
    ['components/evidence/LinkedControlsPanel.tsx', 'linked-controls-panel'],
    ['components/evidence/ProvenanceStatusPanel.tsx', 'provenance-status-panel'],
    ['components/evidence/SnapshotReplayPanel.tsx', 'snapshot-replay-panel'],
  ];
  for (const [f, label] of labels) {
    assert.match(read(f), new RegExp(label), `${f}: missing aria-label="${label}"`);
  }
});
