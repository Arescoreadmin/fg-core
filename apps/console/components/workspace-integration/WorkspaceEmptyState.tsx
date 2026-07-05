import Link from 'next/link';
import { AlertCircle } from 'lucide-react';
import { cn } from '@/lib/cn';
import { Button, buttonVariants } from '@/components/ui/button';

const MCIM_ID = 'MCIM-18.6-WS-EMPTY-STATE';
const AUTHORITY = 'Workspace Empty State Authority';

interface WorkspaceEmptyStateProps {
  workspace: string;
  reason: string;
  dataRequired: string;
  nextAction: string;
  nextActionHref?: string;
  nextActionLabel?: string;
  icon?: React.ElementType;
  mcimId: string;
  className?: string;
}

export default function WorkspaceEmptyState({
  workspace,
  reason,
  dataRequired,
  nextAction,
  nextActionHref,
  nextActionLabel = 'Get Started',
  icon: Icon = AlertCircle,
  mcimId,
  className,
}: WorkspaceEmptyStateProps) {
  return (
    <div
      data-mcim-id={mcimId}
      data-workspace={workspace}
      data-authority={AUTHORITY}
      data-testid="workspace-empty-state"
      className={cn(
        'flex flex-col items-center justify-center gap-4 rounded-lg border border-border bg-surface-2 px-8 py-12 text-center',
        className,
      )}
      role="status"
      aria-label={`Empty state for ${workspace}`}
    >
      <div className="flex h-14 w-14 items-center justify-center rounded-full bg-muted/40">
        <Icon className="h-7 w-7 text-muted" aria-hidden="true" />
      </div>

      <div className="max-w-sm space-y-1.5">
        <p className="text-sm font-semibold text-foreground">{reason}</p>
        <p className="text-xs text-muted">
          <span className="font-medium">Data required:</span> {dataRequired}
        </p>
        <p className="text-xs text-muted">{nextAction}</p>
      </div>

      {nextActionHref ? (
        <Link
          href={nextActionHref}
          className={cn(buttonVariants({ variant: 'default', size: 'sm' }))}
        >
          {nextActionLabel}
        </Link>
      ) : (
        <Button size="sm" variant="outline" disabled>
          {nextActionLabel}
        </Button>
      )}
    </div>
  );
}

// Required MCIM declarations
void MCIM_ID;
void AUTHORITY;
