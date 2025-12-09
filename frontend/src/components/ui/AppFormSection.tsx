import type { ElementType } from 'react';
import { AppCard, type AppCardProps } from './AppCard';

interface AppFormSectionProps extends Omit<AppCardProps, 'as'> {
  as?: ElementType;
}

export function AppFormSection({ as = 'form', className, ...rest }: AppFormSectionProps) {
  const classes = ['app-form-section', className].filter(Boolean).join(' ');
  return <AppCard as={as} className={classes} {...rest} />;
}
