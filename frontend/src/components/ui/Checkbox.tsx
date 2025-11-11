import { forwardRef } from 'react';
import type { InputHTMLAttributes, ReactNode } from 'react';
import { cn } from '@/utils/cn';

interface CheckboxProps extends InputHTMLAttributes<HTMLInputElement> {
  label?: ReactNode;
}

export const Checkbox = forwardRef<HTMLInputElement, CheckboxProps>(function Checkbox(
  { className, label, ...props },
  ref
) {
  return (
    <label className={cn('ui-checkbox', className)}>
      <input ref={ref} type="checkbox" {...props} />
      <span>{label}</span>
    </label>
  );
});
