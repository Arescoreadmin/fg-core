'use client';

import { useState, useCallback } from 'react';
import Link from 'next/link';
import { Search, X } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import WidgetShell from './WidgetShell';
import { CONSOLE_REGISTRY, NavigationSearchIndex } from '@fg/navigation';

// MCIM reference: MCIM-18.6-CMD-CENTER
const MCIM_ID = 'MCIM-18.6-CMD-CENTER';
const AUTHORITY = 'Control Tower Authority';
const sourceOfTruth = '/api/core/control-tower/snapshot';
const drillDown = '/dashboard';

const SEARCH_TARGETS = [
  { id: 'search-capabilities', label: 'Capabilities', query: 'capability' },
  { id: 'search-reports', label: 'Reports', query: 'reports' },
  { id: 'search-assessments', label: 'Assessments', query: 'assessments' },
  { id: 'search-authorities', label: 'Authorities', query: 'governance' },
  { id: 'search-evidence', label: 'Evidence', query: 'evidence' },
  { id: 'search-clients', label: 'Clients', query: 'clients' },
  { id: 'search-policies', label: 'Policies', query: 'policy' },
  { id: 'search-workflow', label: 'Workflow', query: 'workflow' },
] as const;

const searchIndex = new NavigationSearchIndex(CONSOLE_REGISTRY);
searchIndex.build();

interface SearchResult {
  id: string;
  title: string;
  route: string;
  capability: string;
  authority: string;
}

function performSearch(query: string): SearchResult[] {
  if (!query.trim()) return [];
  const raw = searchIndex.search(query, 'console', 8);
  return raw.map((r) => ({
    id: r.item.id,
    title: r.item.title,
    route: r.item.route,
    capability: r.item.metadata.capability,
    authority: r.item.metadata.authority,
  }));
}

interface GlobalSearchProps {
  className?: string;
}

export default function GlobalSearch({ className }: GlobalSearchProps) {
  const [query, setQuery] = useState('');
  const [results, setResults] = useState<SearchResult[]>([]);
  const [activeTarget, setActiveTarget] = useState<string | null>(null);

  const handleSearch = useCallback((q: string) => {
    setQuery(q);
    setResults(performSearch(q));
  }, []);

  const handleTargetClick = useCallback((target: typeof SEARCH_TARGETS[number]) => {
    setActiveTarget(target.id);
    handleSearch(target.query);
  }, [handleSearch]);

  const clearSearch = useCallback(() => {
    setQuery('');
    setResults([]);
    setActiveTarget(null);
  }, []);

  return (
    <WidgetShell
      mcimId={MCIM_ID}
      authority={AUTHORITY}
      capability="Global Search"
      sourceOfTruth={sourceOfTruth}
      drillDown={drillDown}
      refreshPolicy="on-load"
      title="Global Search"
      className={className}
    >
      <div
        aria-label="global-search"
        data-testid="global-search-authority"
      >
        <p className="text-[10px] uppercase tracking-wide text-muted mb-2">
          Authority: {AUTHORITY}
        </p>

        {/* Search input */}
        <div className="relative mb-3">
          <Search
            className="absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted"
            aria-hidden="true"
          />
          <input
            type="search"
            placeholder="Search capabilities, reports, assessments…"
            value={query}
            onChange={(e) => handleSearch(e.target.value)}
            className="w-full rounded-md border border-border bg-background py-1.5 pl-8 pr-8 text-sm text-foreground placeholder:text-muted focus:border-primary focus:outline-none"
            aria-label="global-search-input"
          />
          {query && (
            <Button
              variant="ghost"
              size="sm"
              className="absolute right-1 top-1/2 h-5 w-5 -translate-y-1/2 p-0"
              onClick={clearSearch}
              aria-label="Clear search"
            >
              <X className="h-3 w-3" aria-hidden="true" />
            </Button>
          )}
        </div>

        {/* Quick-access target buttons */}
        <div className="mb-3 flex flex-wrap gap-1.5" aria-label="search-targets">
          {SEARCH_TARGETS.map((target) => (
            <Button
              key={target.id}
              variant={activeTarget === target.id ? 'default' : 'outline'}
              size="sm"
              className="h-6 text-[10px] px-2"
              data-testid={target.id}
              aria-label={target.id}
              onClick={() => handleTargetClick(target)}
            >
              {target.label}
            </Button>
          ))}
        </div>

        {/* Results */}
        {query && results.length === 0 && (
          <p className="text-sm text-muted py-2">No results for &ldquo;{query}&rdquo;</p>
        )}

        {results.length > 0 && (
          <ul className="space-y-1.5" role="listbox" aria-label="search-results">
            {results.map((r) => (
              <li key={r.id} role="option" aria-selected={false}>
                <Link
                  href={r.route}
                  className="flex items-start justify-between gap-2 rounded-md border border-border px-3 py-2 hover:border-primary/40 transition-colors"
                  aria-label={`Navigate to ${r.title}`}
                >
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-medium text-foreground truncate">{r.title}</p>
                    <p className="text-[10px] text-muted truncate">{r.capability}</p>
                  </div>
                  <Badge variant="outline" className="text-[9px] shrink-0">
                    {r.authority.split(' ')[0]}
                  </Badge>
                </Link>
              </li>
            ))}
          </ul>
        )}
      </div>
    </WidgetShell>
  );
}
