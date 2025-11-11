export const mockRbacPolicies = [
  {
    role: 'admin',
    permissions: [
      'dashboard:view',
      'tasks:create',
      'tasks:update',
      'tasks:retry',
      'tasks:cancel',
      'tasks:inventory',
      'reports:view',
      'reports:export',
      'config:update',
      'agents:manage',
      'bas:manage',
      'audit:view',
      'audit:export',
    ],
  },
  {
    role: 'operator',
    permissions: [
      'dashboard:view',
      'tasks:create',
      'tasks:update',
      'tasks:retry',
      'tasks:cancel',
      'reports:view',
      'reports:export',
    ],
  },
  {
    role: 'auditor',
    permissions: ['audit:view', 'audit:export', 'reports:view'],
  },
];
