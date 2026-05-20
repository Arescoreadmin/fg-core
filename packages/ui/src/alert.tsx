import { cva, type VariantProps } from 'class-variance-authority';
import { cn } from './cn';
import { type HTMLAttributes } from 'react';

const alertVariants = cva(
  'relative w-full rounded border px-4 py-3 text-sm',
  {
    variants: {
      variant: {
        default: 'border-border bg-surface-2 text-foreground',
        info: 'border-info/30 bg-info/10 text-info',
        warning: 'border-warning/30 bg-warning/10 text-warning',
        destructive: 'border-danger/30 bg-danger/10 text-danger',
        success: 'border-success/30 bg-success/10 text-success',
      },
    },
    defaultVariants: { variant: 'default' },
  },
);

export interface AlertProps
  extends HTMLAttributes<HTMLDivElement>,
    VariantProps<typeof alertVariants> {}

export function Alert({ className, variant, children, ...props }: AlertProps) {
  return (
    <div role="alert" className={cn(alertVariants({ variant }), className)} {...props}>
      {children}
    </div>
  );
}

export function AlertTitle({ className, ...props }: HTMLAttributes<HTMLParagraphElement>) {
  return <p className={cn('font-semibold leading-none mb-1', className)} {...props} />;
}

export function AlertDescription({ className, ...props }: HTMLAttributes<HTMLParagraphElement>) {
  return <p className={cn('text-sm opacity-90', className)} {...props} />;
}
