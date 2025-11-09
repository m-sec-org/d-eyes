import type { ReactNode } from 'react';
import { Navigate } from 'react-router-dom';
import { usePermissions } from '@/hooks/usePermissions';

interface ProtectedRouteProps {
  children: ReactNode;
  route: string;
  allowedRoles?: Array<'operator' | 'auditor' | 'admin'>;
}

export function ProtectedRoute({ children, route, allowedRoles }: ProtectedRouteProps) {
  const { canAccess } = usePermissions();
  if (!canAccess(route, allowedRoles)) {
    return <Navigate to="/tasks" replace />;
  }
  return <>{children}</>;
}
