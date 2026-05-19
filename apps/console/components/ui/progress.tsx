'use client';

import * as ProgressPrimitive from '@radix-ui/react-progress';
import { cn } from '@/lib/cn';

interface ProgressProps extends React.ComponentPropsWithoutRef<typeof ProgressPrimitive.Root> {
  indicatorClassName?: string;
}

function Progress({ className, value, indicatorClassName, ...props }: ProgressProps) {
  return (
    <ProgressPrimitive.Root
      className={cn('relative h-2 w-full overflow-hidden rounded-full bg-surface-3', className)}
      {...props}
    >
      <ProgressPrimitive.Indicator
        className={cn('h-full w-full flex-1 rounded-full bg-primary transition-all duration-300', indicatorClassName)}
        style={{ transform: `translateX(-${100 - (value ?? 0)}%)` }}
      />
    </ProgressPrimitive.Root>
  );
}

export { Progress };
