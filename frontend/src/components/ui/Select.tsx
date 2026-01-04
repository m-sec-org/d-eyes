import { forwardRef } from 'react';
import type { SelectHTMLAttributes } from 'react';
import { cn } from '@/utils/cn';

export interface SelectProps extends SelectHTMLAttributes<HTMLSelectElement> {
  invalid?: boolean;
}

export const Select = forwardRef<HTMLSelectElement, SelectProps>(function Select(
  { className, invalid, children, ...props },
  ref
) {
  return (
    <select
      ref={ref}
      className={cn('ui-control', 'ui-control--select', invalid && 'ui-control--invalid', className)}
      aria-invalid={invalid}
      {...props}
    >
      {children}
    </select>
  );
});

Select.displayName = 'Select';
