import type { HTMLAttributes, ReactNode } from 'react';

interface AppBulkToolbarProps extends HTMLAttributes<HTMLDivElement> {
  summary: ReactNode;
  actions: ReactNode;
}

export function AppBulkToolbar({ summary, actions, className, ...rest }: AppBulkToolbarProps) {
  const classes = ['app-bulk-toolbar', className].filter(Boolean).join(' ');
  return (
    <div className={classes} {...rest}>
      <div className="app-bulk-toolbar__summary">{summary}</div>
      <div className="app-bulk-toolbar__actions">{actions}</div>
    </div>
  );
}
