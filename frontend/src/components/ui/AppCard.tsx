import type { ElementType, HTMLAttributes, ReactNode } from 'react';

type AppCardElement = ElementType;

export interface AppCardProps extends HTMLAttributes<HTMLElement> {
  as?: AppCardElement;
  title?: ReactNode;
  description?: ReactNode;
  actions?: ReactNode;
  padding?: 'default' | 'compact';
  children: ReactNode;
}

export function AppCard({
  as: Component = 'section',
  title,
  description,
  actions,
  padding = 'default',
  className,
  children,
  ...rest
}: AppCardProps) {
  const classes = [
    'app-card',
    padding === 'compact' ? 'app-card--compact' : undefined,
    className,
  ]
    .filter(Boolean)
    .join(' ');

  const headingContent = typeof title === 'string' ? <h3 className="app-card__title">{title}</h3> : title;
  const descriptionContent =
    typeof description === 'string' ? <p className="app-card__subtitle">{description}</p> : description;

  return (
    <Component className={classes} {...rest}>
      {(title || description || actions) && (
        <div className="app-card__header">
          <div className="app-card__heading">
            {headingContent}
            {descriptionContent}
          </div>
          {actions && <div className="app-card__actions">{actions}</div>}
        </div>
      )}
      <div className="app-card__body">{children}</div>
    </Component>
  );
}
