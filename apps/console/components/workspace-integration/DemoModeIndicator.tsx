import { FlaskConical } from 'lucide-react';
import { cn } from '@/lib/cn';

const MCIM_ID = 'MCIM-18.6-DEMO-MODE-INDICATOR';
const AUTHORITY = 'Demo Mode Authority';

interface DemoModeIndicatorProps {
  active: boolean;
  datasetName?: string;
  children?: React.ReactNode;
  className?: string;
}

export default function DemoModeIndicator({
  active,
  datasetName,
  children,
  className,
}: DemoModeIndicatorProps) {
  if (!active) {
    return <>{children}</>;
  }

  return (
    <div
      data-demo-mode="true"
      data-mcim-id={MCIM_ID}
      data-authority={AUTHORITY}
      className={cn('relative', className)}
    >
      <div
        role="alert"
        aria-live="polite"
        className={cn(
          'flex items-center gap-2 rounded-md border border-amber-400/60 bg-amber-50 px-4 py-2 text-xs font-medium text-amber-800',
          'dark:border-amber-500/40 dark:bg-amber-950/40 dark:text-amber-300',
        )}
      >
        <FlaskConical className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
        <span>
          Demo Mode —{' '}
          <span>
            Data shown is sample fixtures
            {datasetName ? ` (${datasetName})` : ''}.
          </span>{' '}
          Not production data.
        </span>
      </div>

      {active && children && <div className="mt-3">{children}</div>}
    </div>
  );
}

// Required MCIM declarations
void MCIM_ID;
void AUTHORITY;
