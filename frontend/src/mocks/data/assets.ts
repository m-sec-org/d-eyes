const baseAssets = [
  {
    id: 'asset-001',
    hostname: 'prod-web-01',
    ip: '10.0.0.12',
    status: 'online' as const,
    tags: ['prod', 'web'],
    risk_level: 'medium' as const,
    last_seen: '2025-02-19T02:45:00Z',
  },
  {
    id: 'asset-002',
    hostname: 'prod-db-01',
    ip: '10.0.0.21',
    status: 'online' as const,
    tags: ['prod', 'db'],
    risk_level: 'high' as const,
    last_seen: '2025-02-19T02:44:00Z',
  },
  {
    id: 'asset-099',
    hostname: 'edge-cache',
    ip: '192.168.10.9',
    status: 'offline' as const,
    tags: ['edge'],
    risk_level: 'low' as const,
    last_seen: '2025-02-18T22:12:00Z',
  },
];

const extraAssets = Array.from({ length: 27 }).map((_, index) => {
  const id = `asset-extra-${index + 1}`;
  const status = index % 5 === 0 ? 'offline' : index % 7 === 0 ? 'unknown' : 'online';
  const risk = index % 4 === 0 ? 'high' : index % 3 === 0 ? 'medium' : 'low';
  return {
    id,
    hostname: `edge-node-${index + 3}`,
    ip: `10.0.${Math.floor(index / 5) + 5}.${(index % 5) * 10 + 5}`,
    status: status as 'online' | 'offline' | 'unknown',
    tags: status === 'online' ? ['prod'] : ['staging'],
    risk_level: risk as 'low' | 'medium' | 'high',
    last_seen: '2025-02-18T10:00:00Z',
  };
});

export const mockAssets = {
  items: [...baseAssets, ...extraAssets],
  totals: {
    online: 24,
    offline: 5,
    critical: 9,
  },
};
