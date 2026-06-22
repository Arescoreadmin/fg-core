'use client';

import Link from 'next/link';

export interface BreadcrumbItem {
  label: string;
  href?: string;
}

interface Props {
  crumbs: BreadcrumbItem[];
}

export function ConsoleTopNav({ crumbs }: Props) {
  return (
    <nav
      className="sticky top-0 z-40 w-full border-b border-border bg-surface/95 backdrop-blur-sm"
      aria-label="Console navigation"
    >
      <div className="max-w-6xl mx-auto px-4 h-11 flex items-center gap-1.5">
        <Link
          href="/"
          className="text-xs font-semibold text-foreground hover:text-primary transition-colors shrink-0"
        >
          FrostGate
        </Link>

        {crumbs.map((crumb, i) => (
          <span key={i} className="flex items-center gap-1.5 min-w-0">
            <span className="text-muted text-xs select-none">/</span>
            {crumb.href ? (
              <Link
                href={crumb.href}
                className="text-xs text-muted hover:text-foreground transition-colors truncate"
              >
                {crumb.label}
              </Link>
            ) : (
              <span className="text-xs text-foreground font-medium truncate max-w-[200px]">
                {crumb.label}
              </span>
            )}
          </span>
        ))}
      </div>
    </nav>
  );
}
