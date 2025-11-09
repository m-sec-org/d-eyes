const baseUser = {
  display_name: 'SecOps Lead',
  capabilities: ['tasks:create', 'tasks:retry', 'config:update'],
};

export const mockUsers = {
  'ops.lead': {
    password: 'Passw0rd!',
    role: 'admin',
    ...baseUser,
  },
  'audit.user': {
    password: 'Passw0rd!',
    role: 'auditor',
    display_name: '审计专员',
    capabilities: ['audit:export'],
  },
};
