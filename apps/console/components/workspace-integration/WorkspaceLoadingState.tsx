import { cn } from '@/lib/cn';

const MCIM_ID = 'MCIM-18.6-WS-LOADING-STATE';
const AUTHORITY = 'Workspace Loading State Authority';

interface WorkspaceLoadingStateProps {
  workspace: string;
  sections?: number;
  showHeader?: boolean;
  mcimId: string;
  className?: string;
}

/** Deterministic skeleton widths — no Math.random, no Date.now. */
const SKELETON_WIDTHS = ['w-full', 'w-4/5', 'w-3/5', 'w-full', 'w-2/3', 'w-1/2', 'w-full', 'w-3/4'] as const;

function SkeletonSection({ index }: { index: number }) {
  // Use index to deterministically pick widths
  const titleWidth = SKELETON_WIDTHS[index % SKELETON_WIDTHS.length];
  const line1Width = SKELETON_WIDTHS[(index + 2) % SKELETON_WIDTHS.length];
  const line2Width = SKELETON_WIDTHS[(index + 4) % SKELETON_WIDTHS.length];

  return (
    <div className="space-y-2.5" aria-hidden="true">
      <div className={cn('h-4 animate-pulse rounded bg-muted', titleWidth)} />
      <div className={cn('h-3 animate-pulse rounded bg-muted', line1Width)} />
      <div className={cn('h-3 animate-pulse rounded bg-muted', line2Width)} />
    </div>
  );
}

export default function WorkspaceLoadingState({
  workspace,
  sections = 3,
  showHeader = true,
  mcimId,
  className,
}: WorkspaceLoadingStateProps) {
  const clampedSections = Math.max(1, Math.min(sections, 8));

  return (
    <div
      data-mcim-id={mcimId}
      data-workspace={workspace}
      data-authority={AUTHORITY}
      className={cn('space-y-6 p-4', className)}
      role="status"
      aria-label={`Loading ${workspace}`}
      aria-busy="true"
    >
      <span className="sr-only">Loading {workspace}…</span>

      {showHeader && (
        <div className="space-y-2" aria-hidden="true">
          <div className="h-5 w-2/5 animate-pulse rounded bg-muted" />
          <div className="h-3 w-1/3 animate-pulse rounded bg-muted" />
        </div>
      )}

      {Array.from({ length: clampedSections }, (_, i) => (
        <SkeletonSection key={i} index={i} />
      ))}
    </div>
  );
}

// Required MCIM declarations
void MCIM_ID;
void AUTHORITY;
