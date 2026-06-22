'use client';

import { ChevronDown } from 'lucide-react';
import { Card, CardContent } from '@/components/ui/card';
import {
  type EvidenceFilterState,
  type TrustState,
} from '@/lib/evidenceApi';

interface InvestigationFiltersProps {
  filters: EvidenceFilterState;
  onChange: (f: EvidenceFilterState) => void;
  evidenceTypes: string[];
  classifications: string[];
  totalCount: number;
  filteredCount: number;
}

const TRUST_STATES: TrustState[] = [
  'valid', 'invalid', 'missing', 'stale', 'unknown', 'unverifiable', 'restricted',
];

function trustStateLabel(s: TrustState): string {
  const labels: Record<TrustState, string> = {
    valid: 'Valid',
    invalid: 'Invalid',
    missing: 'Missing',
    stale: 'Stale',
    unknown: 'Unknown',
    unverifiable: 'Unverifiable',
    restricted: 'Restricted',
  };
  return labels[s];
}

function SelectField({
  id,
  label,
  value,
  onChange,
  options,
  placeholder,
}: {
  id: string;
  label: string;
  value: string;
  onChange: (v: string) => void;
  options: { value: string; label: string }[];
  placeholder: string;
}) {
  return (
    <div className="flex flex-col gap-1">
      <label htmlFor={id} className="text-xs font-medium text-muted-foreground">
        {label}
      </label>
      <div className="relative">
        <select
          id={id}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          className="w-full appearance-none rounded border border-border bg-background px-3 py-1.5 pr-7 text-xs focus:outline-none focus:ring-2 focus:ring-ring"
          aria-label={label}
        >
          <option value="">{placeholder}</option>
          {options.map((o) => (
            <option key={o.value} value={o.value}>
              {o.label}
            </option>
          ))}
        </select>
        <ChevronDown
          className="pointer-events-none absolute right-2 top-2 h-3.5 w-3.5 text-muted"
          aria-hidden="true"
        />
      </div>
    </div>
  );
}

export function InvestigationFilters({
  filters,
  onChange,
  evidenceTypes,
  classifications,
  totalCount,
  filteredCount,
}: InvestigationFiltersProps) {
  function set<K extends keyof EvidenceFilterState>(k: K, v: EvidenceFilterState[K]) {
    onChange({ ...filters, [k]: v });
  }

  return (
    <Card aria-label="investigation-filters">
      <CardContent className="pt-4">
        <div className="flex flex-wrap items-end gap-3">
          <SelectField
            id="filter-evidence-type"
            label="Evidence Type"
            value={filters.evidenceType}
            onChange={(v) => set('evidenceType', v)}
            options={evidenceTypes.map((t) => ({ value: t, label: t }))}
            placeholder="All types"
          />
          <SelectField
            id="filter-classification"
            label="Classification"
            value={filters.classification}
            onChange={(v) => set('classification', v)}
            options={classifications.map((c) => ({ value: c, label: c }))}
            placeholder="All classifications"
          />
          <SelectField
            id="filter-trust-state"
            label="Trust State"
            value={filters.trustState}
            onChange={(v) => set('trustState', v)}
            options={TRUST_STATES.map((s) => ({ value: s, label: trustStateLabel(s) }))}
            placeholder="All states"
          />
          <SelectField
            id="filter-has-controls"
            label="Controls Linked"
            value={filters.hasControls === null ? '' : String(filters.hasControls)}
            onChange={(v) => set('hasControls', v === '' ? null : v === 'true')}
            options={[
              { value: 'true', label: 'Has linked controls' },
              { value: 'false', label: 'No linked controls' },
            ]}
            placeholder="Any"
          />
          <SelectField
            id="filter-sort-order"
            label="Sort Order"
            value={filters.sortOrder}
            onChange={(v) => set('sortOrder', v as 'asc' | 'desc')}
            options={[
              { value: 'desc', label: 'Newest first' },
              { value: 'asc', label: 'Oldest first' },
            ]}
            placeholder=""
          />
          {(filters.evidenceType || filters.classification || filters.trustState || filters.hasControls !== null) && (
            <button
              onClick={() =>
                onChange({
                  evidenceType: '',
                  classification: '',
                  trustState: '',
                  hasControls: null,
                  sortOrder: filters.sortOrder,
                })
              }
              className="rounded border border-border px-2 py-1.5 text-xs text-muted-foreground hover:text-foreground"
              aria-label="Clear all filters"
            >
              Clear filters
            </button>
          )}
          <p className="ml-auto text-xs text-muted-foreground" aria-label="filter-result-count">
            {filteredCount === totalCount
              ? `${totalCount} item${totalCount !== 1 ? 's' : ''}`
              : `${filteredCount} of ${totalCount}`}
          </p>
        </div>
      </CardContent>
    </Card>
  );
}
