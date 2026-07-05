'use client';

import { useCallback } from 'react';
import Link from 'next/link';
import { ArrowRight } from 'lucide-react';
import { cn } from '@/lib/cn';
import { buildWorkspaceUrl } from '@/lib/workspaceContext';
import type { WorkspaceContext, WorkspaceContextKey } from '@/lib/workspaceContext';

const MCIM_ID = 'MCIM-18.6-CROSS-WS-NAV';
const AUTHORITY = 'Cross-Workspace Navigation Authority';

export interface WorkspaceLink {
  id: string;
  label: string;
  route: string;
  icon?: React.ElementType;
  description?: string;
  /** Keys to forward from active context — only declared keys are included; stale keys are dropped. */
  contextParams?: WorkspaceContextKey[];
  mcimId: string;
}

interface CrossWorkspaceNavProps {
  currentWorkspace: string;
  context?: WorkspaceContext;
  links: WorkspaceLink[];
  layout?: 'horizontal' | 'vertical' | 'grid';
  size?: 'sm' | 'md';
  showCurrent?: boolean;
}

export default function CrossWorkspaceNav({
  currentWorkspace,
  context,
  links,
  layout = 'horizontal',
  size = 'md',
  showCurrent = true,
}: CrossWorkspaceNavProps) {
  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent<HTMLAnchorElement>) => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        (e.currentTarget as HTMLAnchorElement).click();
      }
    },
    [],
  );

  const resolveHref = (link: WorkspaceLink): string => {
    // Only forward context keys explicitly declared in contextParams.
    // Stale keys (e.g. report, finding) are not propagated unless the target link requests them.
    const filtered: WorkspaceContext = {};
    if (context && link.contextParams) {
      for (const key of link.contextParams) {
        const val = context[key];
        if (val !== undefined) {
          (filtered as Record<string, string | undefined>)[key] = val;
        }
      }
    }
    return buildWorkspaceUrl(link.route, filtered);
  };

  const listClasses = cn(
    'flex gap-2',
    layout === 'horizontal' && 'flex-wrap flex-row items-center',
    layout === 'vertical' && 'flex-col',
    layout === 'grid' && 'grid grid-cols-2 sm:grid-cols-3',
  );

  const linkBaseClasses = cn(
    'inline-flex items-center gap-2 rounded font-medium transition-colors',
    'focus-visible:outline focus-visible:outline-2 focus-visible:outline-primary',
    size === 'sm' && 'px-2 py-1 text-xs',
    size === 'md' && 'px-3 py-1.5 text-sm',
  );

  const visibleLinks = showCurrent
    ? links
    : links.filter((l) => l.id !== currentWorkspace);

  return (
    <nav
      aria-label="cross-workspace navigation"
      data-mcim-id={MCIM_ID}
      data-workspace={currentWorkspace}
      data-authority={AUTHORITY}
    >
      <ol className={listClasses} role="list">
        {visibleLinks.map((link) => {
          const isCurrent = link.id === currentWorkspace;
          const Icon = link.icon;
          const href = resolveHref(link);

          return (
            <li key={link.id}>
              <Link
                href={href}
                aria-current={isCurrent ? 'page' : undefined}
                aria-label={link.description ? `${link.label}: ${link.description}` : link.label}
                data-mcim-id={link.mcimId}
                data-workspace-link={link.id}
                onKeyDown={handleKeyDown}
                className={cn(
                  linkBaseClasses,
                  isCurrent
                    ? 'bg-primary text-white'
                    : 'bg-surface-2 text-foreground hover:bg-surface-3',
                )}
              >
                {Icon && <Icon className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />}
                <span>{link.label}</span>
              </Link>
            </li>
          );
        })}
      </ol>
    </nav>
  );
}

// Required MCIM declarations
void MCIM_ID;
void AUTHORITY;
