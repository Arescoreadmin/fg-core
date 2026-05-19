'use client';

import { useCallback, useEffect, useMemo, useState } from 'react';
import { ShieldCheck } from 'lucide-react';
import { TopBar } from '@/components/layout/TopBar';
import {
  type EvidenceReference,
  type EvidenceFilterState,
  DEFAULT_FILTERS,
  listEvidence,
  applyEvidenceFilters,
  collectFilterOptions,
} from '@/lib/evidenceApi';
import {
  AuditChainPanel,
  ChainOfCustodyPanel,
  EvidenceDetailPanel,
  EvidenceTimeline,
  InvestigationFilters,
  LinkedControlsPanel,
  ProvenanceStatusPanel,
  SnapshotReplayPanel,
} from '@/components/evidence';

const DEFAULT_ASSESSMENT_ID = process.env.NEXT_PUBLIC_DEFAULT_ASSESSMENT_ID ?? '';

export default function ProvenancePage() {
  const [allItems, setAllItems] = useState<EvidenceReference[]>([]);
  const [loading, setLoading] = useState(false);
  const [fetchError, setFetchError] = useState<string | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [filters, setFilters] = useState<EvidenceFilterState>(DEFAULT_FILTERS);
  const [assessmentId] = useState<string>(DEFAULT_ASSESSMENT_ID);

  useEffect(() => {
    if (!assessmentId) return;
    let cancelled = false;
    setLoading(true);
    setFetchError(null);
    setAllItems([]);

    const PAGE_SIZE = 200;
    const MAX_PAGES = 25; // safety cap: 5 000 items

    (async () => {
      const accumulated: EvidenceReference[] = [];
      for (let page = 0; page < MAX_PAGES; page++) {
        const result = await listEvidence(assessmentId, PAGE_SIZE, page * PAGE_SIZE);
        if (cancelled) return;
        if (!result.ok) {
          setFetchError(result.error);
          setLoading(false);
          return;
        }
        accumulated.push(...result.data);
        if (result.data.length < PAGE_SIZE) break;
      }
      if (!cancelled) {
        setAllItems(accumulated);
        setLoading(false);
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [assessmentId]);

  const { evidenceTypes, classifications } = useMemo(
    () => collectFilterOptions(allItems),
    [allItems],
  );

  const filtered = useMemo(() => applyEvidenceFilters(allItems, filters), [allItems, filters]);

  const selectedEvidence = useMemo(
    () => filtered.find((e) => e.evidence_id === selectedId) ?? null,
    [filtered, selectedId],
  );

  const handleSelect = useCallback((id: string) => {
    setSelectedId(id);
  }, []);

  return (
    <div className="flex flex-col" aria-label="provenance-page">
      <TopBar title="Evidence Explorer" subtitle="Provenance investigation and audit chain review" />
      <div className="space-y-4 p-6">

        {/* Page header */}
        <div className="flex items-center gap-2">
          <ShieldCheck className="h-5 w-5 text-primary" aria-hidden="true" />
          <div>
            <h1 className="text-sm font-semibold text-foreground">
              Enterprise Evidence Investigation Console
            </h1>
            <p className="text-xs text-muted-foreground">
              Operator-grade provenance investigation, audit chain review, and chain-of-custody
              readiness. All trust decisions are server-authoritative.
            </p>
          </div>
        </div>

        {/* Error state */}
        {fetchError && (
          <div
            className="rounded border border-risk-critical/30 bg-risk-critical/10 px-4 py-3 text-xs text-risk-critical"
            aria-label="evidence-fetch-error"
          >
            {fetchError === 'Network error — core unreachable'
              ? 'Evidence API is unreachable. Check backend connectivity.'
              : fetchError}
          </div>
        )}

        {/* Loading state */}
        {loading && (
          <div
            className="text-xs text-muted-foreground"
            aria-label="evidence-loading"
          >
            Loading evidence…
          </div>
        )}

        {/* Filters */}
        {!loading && !fetchError && assessmentId && (
          <InvestigationFilters
            filters={filters}
            onChange={setFilters}
            evidenceTypes={evidenceTypes}
            classifications={classifications}
            totalCount={allItems.length}
            filteredCount={filtered.length}
          />
        )}

        {/* No assessment configured */}
        {!assessmentId && (
          <div
            className="rounded border border-border bg-surface-2 px-4 py-6 text-center text-xs text-muted-foreground"
            aria-label="evidence-no-assessment"
          >
            No assessment configured. Set NEXT_PUBLIC_DEFAULT_ASSESSMENT_ID to load evidence.
          </div>
        )}

        {/* Audit chain — always visible, fetches independently */}
        <AuditChainPanel />

        {/* Main investigation layout */}
        <div className="grid gap-4 lg:grid-cols-[1fr_1fr]">
          {/* Left: timeline */}
          <EvidenceTimeline
            items={filtered}
            selectedId={selectedId}
            onSelect={handleSelect}
          />

          {/* Right: detail panels */}
          <div className="space-y-4">
            <EvidenceDetailPanel evidence={selectedEvidence} />
            <ProvenanceStatusPanel evidence={selectedEvidence} />
            <LinkedControlsPanel evidence={selectedEvidence} />
            <ChainOfCustodyPanel evidence={selectedEvidence} />
            <SnapshotReplayPanel evidence={selectedEvidence} assessmentId={assessmentId || null} />
          </div>
        </div>

        {/* Legal review seam — Gap B */}
        {/* aria-label="legal-review-panel" reserved */}

        {/* Signed evidence seam — Gap C */}
        {/* aria-label="signed-evidence-panel" reserved */}

      </div>
    </div>
  );
}
