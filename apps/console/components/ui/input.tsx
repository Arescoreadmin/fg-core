import { cn } from '@/lib/cn';
import { forwardRef } from 'react';

const Input = forwardRef<HTMLInputElement, React.InputHTMLAttributes<HTMLInputElement>>(
  ({ className, type, ...props }, ref) => (
    <input
      type={type}
      ref={ref}
      className={cn(
        'flex h-10 w-full rounded border border-border bg-surface-2 px-3 py-2 text-sm text-foreground placeholder:text-muted',
        'focus:outline-none focus:ring-1 focus:ring-primary focus:border-primary',
        'disabled:cursor-not-allowed disabled:opacity-50',
        'transition-colors',
        className
      )}
      {...props}
    />
  )
);
Input.displayName = 'Input';

export { Input };
