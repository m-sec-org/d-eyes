import { mockAssets } from './assets';

export const mockAssetDetails = mockAssets.items.reduce<Record<string, any>>((acc, asset) => {
  acc[asset.id] = {
    ...asset,
    platform: asset.id === 'asset-001' ? 'Linux' : 'Windows',
    owner: asset.tags.includes('prod') ? 'SecOps Team' : 'Platform Team',
    related_tasks: [
      {
        id: 'task-' + asset.id,
        type: 'respond',
        status: 'succeeded',
        completed_at: '2025-02-18T11:40:39Z',
      },
    ],
    related_risks: [
      {
        id: 'risk-' + asset.id,
        severity: 'medium',
        summary: '端口暴露警告',
        timestamp: '2025-02-19T02:43:12Z',
      },
    ],
    operations: [
      { actor: 'ops.lead', action: '更新标签', timestamp: '2025-02-18T22:12:00Z' },
    ],
  };
  return acc;
}, {});
