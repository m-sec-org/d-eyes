import { useAuth } from './useAuth';

export type Role = 'operator' | 'auditor' | 'admin';

const routeRoles: Record<string, Role[]> = {
  '/': ['operator', 'admin'],
  '/tasks': ['operator', 'admin'],
  '/risks': ['operator', 'auditor', 'admin'],
  '/assets': ['operator', 'admin'],
  '/threat-intel': ['operator', 'admin'],
  '/anomalies': ['operator', 'auditor', 'admin'],
  '/queues': ['admin'],
  '/topology': ['admin'],
  '/bas': ['admin'],
  '/playbooks': ['admin'],
  '/compliance': ['admin'],
  '/agents': ['admin'],
  '/reports': ['admin'],
  '/settings': ['admin'],
  '/audit': ['auditor', 'admin'],
  '/ui-guide': ['admin'],
};

const rolePriority: Role[] = ['operator', 'auditor', 'admin'];

export function usePermissions() {
  const { session } = useAuth();
  const role: Role = session?.user.role ?? 'operator';

  const canAccess = (route: string, allowed?: Role[]) => {
    const list = allowed ?? routeRoles[route];
    if (!list) return true;
    return list.includes(role);
  };

  const hasCapability = (capability: string) => session?.user.capabilities?.includes(capability) ?? false;

  return {
    role,
    canAccess,
    hasCapability,
    rolePriority,
  };
}
