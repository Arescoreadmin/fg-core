'use client';

import { useState, useRef, useCallback, useId } from 'react';
import { useRouter } from 'next/navigation';
import { Search, Loader2, X } from 'lucide-react';
import { cn } from '@/lib/cn';

const MCIM_ID = 'MCIM-18.6-WS-SEARCH';
const AUTHORITY = 'Workspace Search Authority';

interface SearchResult {
  id: string;
  title: string;
  workspace: string;
  route: string;
  mcimId: string;
  authority: string;
  excerpt?: string;
}

interface WorkspaceSearchProps {
  onSearch?: (query: string) => Promise<SearchResult[]>;
  placeholder?: string;
  groupByWorkspace?: boolean;
  className?: string;
}

function groupResults(results: SearchResult[]): Map<string, SearchResult[]> {
  const map = new Map<string, SearchResult[]>();
  for (const result of results) {
    const existing = map.get(result.workspace) ?? [];
    existing.push(result);
    map.set(result.workspace, existing);
  }
  return map;
}

export default function WorkspaceSearch({
  onSearch,
  placeholder = 'Search across workspaces…',
  groupByWorkspace = true,
  className,
}: WorkspaceSearchProps) {
  const [query, setQuery] = useState('');
  const [results, setResults] = useState<SearchResult[]>([]);
  const [loading, setLoading] = useState(false);
  const [open, setOpen] = useState(false);
  const [activeIndex, setActiveIndex] = useState(-1);

  const router = useRouter();
  const inputRef = useRef<HTMLInputElement>(null);
  const listboxId = useId();
  const searchId = useId();

  const flatResults = groupByWorkspace
    ? [...groupResults(results).values()].flat()
    : results;

  const handleChange = useCallback(
    async (e: React.ChangeEvent<HTMLInputElement>) => {
      const value = e.target.value;
      setQuery(value);
      setActiveIndex(-1);

      if (!value.trim() || !onSearch) {
        setResults([]);
        setOpen(false);
        return;
      }

      setLoading(true);
      setOpen(true);
      try {
        const found = await onSearch(value.trim());
        setResults(found);
      } finally {
        setLoading(false);
      }
    },
    [onSearch],
  );

  const navigate = useCallback(
    (result: SearchResult) => {
      setOpen(false);
      setQuery('');
      setResults([]);
      router.push(result.route);
    },
    [router],
  );

  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent<HTMLInputElement>) => {
      if (!open) return;

      if (e.key === 'ArrowDown') {
        e.preventDefault();
        setActiveIndex((i) => Math.min(i + 1, flatResults.length - 1));
      } else if (e.key === 'ArrowUp') {
        e.preventDefault();
        setActiveIndex((i) => Math.max(i - 1, -1));
      } else if (e.key === 'Enter') {
        e.preventDefault();
        if (activeIndex >= 0 && flatResults[activeIndex]) {
          navigate(flatResults[activeIndex]);
        }
      } else if (e.key === 'Escape') {
        e.preventDefault();
        setOpen(false);
        setActiveIndex(-1);
      }
    },
    [open, flatResults, activeIndex, navigate],
  );

  const handleResultKeyDown = useCallback(
    (e: React.KeyboardEvent<HTMLLIElement>, result: SearchResult) => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        navigate(result);
      }
    },
    [navigate],
  );

  const clear = useCallback(() => {
    setQuery('');
    setResults([]);
    setOpen(false);
    setActiveIndex(-1);
    inputRef.current?.focus();
  }, []);

  const grouped = groupByWorkspace ? groupResults(results) : null;

  return (
    <div
      className={cn('relative w-full', className)}
      data-mcim-id={MCIM_ID}
      data-authority={AUTHORITY}
      data-testid="workspace-search-root"
    >
      <div className="relative">
        <Search
          className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted"
          aria-hidden="true"
        />
        <input
          ref={inputRef}
          id={searchId}
          type="search"
          role="combobox"
          aria-expanded={open}
          aria-controls={listboxId}
          aria-autocomplete="list"
          aria-activedescendant={
            activeIndex >= 0 && flatResults[activeIndex]
              ? `ws-result-${flatResults[activeIndex].id}`
              : undefined
          }
          aria-label="Search across workspaces"
          placeholder={placeholder}
          value={query}
          onChange={handleChange}
          onKeyDown={handleKeyDown}
          autoComplete="off"
          spellCheck={false}
          data-testid="workspace-search-input"
          className={cn(
            'w-full rounded-md border border-border bg-surface-2 py-2 pl-9 pr-9 text-sm text-foreground',
            'placeholder:text-muted focus:outline-none focus:ring-1 focus:ring-primary',
          )}
        />
        {loading ? (
          <Loader2
            className="pointer-events-none absolute right-3 top-1/2 h-4 w-4 -translate-y-1/2 animate-spin text-muted"
            aria-hidden="true"
          />
        ) : query ? (
          <button
            type="button"
            aria-label="Clear search"
            onClick={clear}
            className="absolute right-3 top-1/2 -translate-y-1/2 text-muted hover:text-foreground focus-visible:outline focus-visible:outline-2 focus-visible:outline-primary rounded"
            data-testid="workspace-search-clear"
          >
            <X className="h-4 w-4" />
          </button>
        ) : null}
      </div>

      {open && (
        <ul
          id={listboxId}
          role="listbox"
          aria-label="Search results"
          data-testid="workspace-search-results"
          className={cn(
            'absolute z-50 mt-1 w-full overflow-auto rounded-md border border-border bg-surface-1 py-1 shadow-lg',
            'max-h-80',
          )}
        >
          {results.length === 0 && !loading && (
            <li
              role="option"
              aria-selected="false"
              className="px-4 py-3 text-sm text-muted"
              data-testid="workspace-search-no-results"
            >
              No results found for &ldquo;{query}&rdquo;
            </li>
          )}

          {grouped
            ? Array.from(grouped.entries()).map(([workspace, items]) => (
                <li key={workspace} role="presentation">
                  <div
                    className="px-3 py-1 text-[10px] font-semibold uppercase tracking-wide text-muted"
                    aria-hidden="true"
                  >
                    {workspace}
                  </div>
                  <ul role="group" aria-label={workspace}>
                    {items.map((result) => {
                      const flatIdx = flatResults.indexOf(result);
                      const isActive = flatIdx === activeIndex;
                      return (
                        <li
                          key={result.id}
                          id={`ws-result-${result.id}`}
                          role="option"
                          aria-selected={isActive}
                          tabIndex={-1}
                          data-mcim-id={result.mcimId}
                          data-testid={`ws-result-${result.id}`}
                          onKeyDown={(e) => handleResultKeyDown(e, result)}
                          onClick={() => navigate(result)}
                          className={cn(
                            'flex cursor-pointer flex-col px-4 py-2 text-sm',
                            isActive
                              ? 'bg-primary/10 text-foreground'
                              : 'text-foreground hover:bg-surface-2',
                          )}
                        >
                          <span className="font-medium">{result.title}</span>
                          {result.excerpt && (
                            <span className="line-clamp-1 text-xs text-muted">
                              {result.excerpt}
                            </span>
                          )}
                        </li>
                      );
                    })}
                  </ul>
                </li>
              ))
            : flatResults.map((result, flatIdx) => {
                const isActive = flatIdx === activeIndex;
                return (
                  <li
                    key={result.id}
                    id={`ws-result-${result.id}`}
                    role="option"
                    aria-selected={isActive}
                    tabIndex={-1}
                    data-mcim-id={result.mcimId}
                    data-testid={`ws-result-${result.id}`}
                    onKeyDown={(e) => handleResultKeyDown(e, result)}
                    onClick={() => navigate(result)}
                    className={cn(
                      'flex cursor-pointer flex-col px-4 py-2 text-sm',
                      isActive
                        ? 'bg-primary/10 text-foreground'
                        : 'text-foreground hover:bg-surface-2',
                    )}
                  >
                    <span className="font-medium">{result.title}</span>
                    {result.excerpt && (
                      <span className="line-clamp-1 text-xs text-muted">{result.excerpt}</span>
                    )}
                  </li>
                );
              })}
        </ul>
      )}
    </div>
  );
}

// Required MCIM declarations
void MCIM_ID;
void AUTHORITY;
