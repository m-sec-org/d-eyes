import type { HTMLAttributes, ReactNode } from 'react';

interface AppStickyToolbarProps extends HTMLAttributes<HTMLDivElement> {
  headline?: ReactNode;
  description?: ReactNode;
  meta?: ReactNode;
  actions?: ReactNode;
  footer?: ReactNode;
}

export function AppStickyToolbar({
  headline,
  description,
  meta,
  actions,
  footer,
  className,
  children,
  ...rest
}: AppStickyToolbarProps) {
  const classes = ['app-sticky-toolbar', className].filter(Boolean).join(' ');
  return (
    <div className={classes} {...rest}>
      <div className="app-sticky-toolbar__body">
        <div className="app-sticky-toolbar__headline">
          {headline && <div className="app-sticky-toolbar__title">{headline}</div>}
          {description && <p className="app-sticky-toolbar__description">{description}</p>}
          {meta}
          {children}
        </div>
        {actions && <div className="app-sticky-toolbar__actions">{actions}</div>}
      </div>
      {footer && <div className="app-sticky-toolbar__footer">{footer}</div>}
    </div>
  );
}
