'use client';

import { useState } from 'react';
import { cn } from '@/lib/cn';

export interface Citation {
  index: number;
  source: string;
  excerpt?: string;
  url?: string;
}

function CitationItem({ c }: { c: Citation }) {
  const [expanded, setExpanded] = useState(false);
  const truncated = c.excerpt && c.excerpt.length > 120 && !expanded;

  return (
    <li className="flex gap-2.5 py-2 border-b border-border last:border-0">
      <span className="mt-0.5 flex h-4 w-4 shrink-0 items-center justify-center rounded bg-info/10 font-mono text-[10px] font-semibold text-info">
        {c.index}
      </span>
      <div className="flex-1 min-w-0">
        {c.url ? (
          <a
            href={c.url}
            target="_blank"
            rel="noreferrer"
            className="text-xs font-medium text-info hover:underline break-all"
          >
            {c.source}
          </a>
        ) : (
          <p className="text-xs font-medium text-foreground break-all">{c.source}</p>
        )}
        {c.excerpt && (
          <>
            <p className="mt-0.5 text-xs text-muted">
              {truncated ? `${c.excerpt.slice(0, 120)}…` : c.excerpt}
            </p>
            {c.excerpt.length > 120 && (
              <button
                onClick={() => setExpanded((v) => !v)}
                className="mt-0.5 text-[10px] text-muted/60 hover:text-muted"
              >
                {expanded ? 'Show less' : 'Show more'}
              </button>
            )}
          </>
        )}
      </div>
    </li>
  );
}

export function CitationViewer({
  citations,
  className,
}: {
  citations: Citation[];
  className?: string;
}) {
  if (!citations.length) return null;

  return (
    <div className={cn('rounded-lg border bg-surface-2 p-3', className)}>
      <p className="mb-2 text-[10px] font-semibold uppercase tracking-widest text-muted/70">
        Sources ({citations.length})
      </p>
      <ul>
        {citations.map((c) => (
          <CitationItem key={c.index} c={c} />
        ))}
      </ul>
    </div>
  );
}
