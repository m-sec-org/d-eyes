import type { ButtonHTMLAttributes, ReactNode } from 'react';
import { cn } from '@/utils/cn';

export type ButtonVariant = 'primary' | 'secondary' | 'ghost' | 'danger' | 'ghost-danger';
export type ButtonSize = 'md' | 'sm';

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant;
  size?: ButtonSize;
  block?: boolean;
  leadingIcon?: ReactNode;
  trailingIcon?: ReactNode;
  danger?: boolean;
}

export function Button({
  variant = 'primary',
  size = 'md',
  block,
  className,
  leadingIcon,
  trailingIcon,
  children,
  danger,
  ...props
}: ButtonProps) {
  const composedVariant = danger ? 'danger' : variant;

  return (
    <button
      className={cn(
        'ui-button',
        `ui-button--${composedVariant}`,
        size === 'sm' && 'ui-button--sm',
        block && 'ui-button--block',
        className
      )}
      {...props}
    >
      {leadingIcon}
      {children}
      {trailingIcon}
    </button>
  );
}
