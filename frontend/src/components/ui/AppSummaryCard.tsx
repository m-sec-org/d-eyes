import type { HTMLAttributes, ReactNode } from 'react';

export type AppSummaryTone = 'neutral' | 'danger' | 'warning' | 'success' | 'info';

interface AppSummaryCardProps extends HTMLAttributes<HTMLDivElement> {
  label: ReactNode;
  value: ReactNode;
  tone?: AppSummaryTone;
  hint?: ReactNode;
}

export function AppSummaryCard({ label, value, tone = 'neutral', hint, className, ...rest }: AppSummaryCardProps) {
  const classes = ['app-summary-card', tone !== 'neutral' ? `tone-${tone}` : null, className]
    .filter(Boolean)
    .join(' ');
  return (
    <div className={classes} {...rest}>
      <span className="app-summary-card__label">{label}</span>
      <strong className="app-summary-card__value">{value}</strong>
      {hint && <span className="app-summary-card__hint">{hint}</span>}
    </div>
  );
}
