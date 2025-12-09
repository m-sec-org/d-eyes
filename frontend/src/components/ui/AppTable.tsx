import type { HTMLAttributes, ReactNode } from 'react';

interface AppTableProps extends HTMLAttributes<HTMLDivElement> {
  title?: ReactNode;
  description?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
}

export function AppTable({ title, description, actions, className, children, ...rest }: AppTableProps) {
  const classes = ['app-table', className].filter(Boolean).join(' ');

  return (
    <div className={classes} {...rest}>
      {(title || description || actions) && (
        <div className="app-table__header">
          <div>
            {typeof title === 'string' ? <strong>{title}</strong> : title}
            {description && <p className="muted">{description}</p>}
          </div>
          {actions && <div className="app-card__actions">{actions}</div>}
        </div>
      )}
      <div className="app-table__body">{children}</div>
    </div>
  );
}
