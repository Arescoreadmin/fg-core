import { cva, type VariantProps } from 'class-variance-authority';
import { cn } from '@/lib/cn';
import { forwardRef } from 'react';

const buttonVariants = cva(
  'inline-flex items-center justify-center gap-2 rounded font-medium transition-all duration-150 disabled:pointer-events-none disabled:opacity-50 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-primary text-sm',
  {
    variants: {
      variant: {
        default: 'bg-primary text-white hover:bg-primary-hover',
        outline: 'border border-border bg-transparent text-foreground hover:bg-surface-2',
        ghost: 'bg-transparent text-foreground hover:bg-surface-2',
        destructive: 'bg-danger text-white hover:bg-danger/90',
        secondary: 'bg-surface-2 text-foreground hover:bg-surface-3',
        link: 'underline-offset-4 hover:underline text-primary bg-transparent p-0 h-auto',
      },
      size: {
        sm: 'h-8 px-3 text-xs',
        md: 'h-10 px-4',
        lg: 'h-12 px-6 text-base',
        icon: 'h-10 w-10',
      },
    },
    defaultVariants: {
      variant: 'default',
      size: 'md',
    },
  }
);

export interface ButtonProps
  extends React.ButtonHTMLAttributes<HTMLButtonElement>,
    VariantProps<typeof buttonVariants> {
  loading?: boolean;
}

const Button = forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant, size, loading, children, disabled, ...props }, ref) => (
    <button
      ref={ref}
      className={cn(buttonVariants({ variant, size }), className)}
      disabled={disabled || loading}
      {...props}
    >
      {loading ? (
        <span className="h-4 w-4 animate-spin rounded-full border-2 border-current border-t-transparent" />
      ) : null}
      {children}
    </button>
  )
);
Button.displayName = 'Button';

export { Button, buttonVariants };
