import type { ReactNode } from 'react';
import { cn } from '@/utils/cn';

interface FormFieldProps {
  label?: ReactNode;
  hint?: ReactNode;
  error?: ReactNode;
  required?: boolean;
  inline?: boolean;
  children: ReactNode;
  htmlFor?: string;
  className?: string;
}

export function FormField({ label, hint, error, required, inline, children, htmlFor, className }: FormFieldProps) {
  return (
    <label className={cn('ui-field', inline && 'ui-field--inline', className)} htmlFor={htmlFor}>
      {label && (
        <span className="ui-field__label">
          {label}
          {required && <span aria-hidden="true">*</span>}
        </span>
      )}
      {children}
      {error ? <span className="ui-field__error">{error}</span> : hint ? <span className="ui-field__hint">{hint}</span> : null}
    </label>
  );
}
