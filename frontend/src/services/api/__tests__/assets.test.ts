import { describe, expect, it } from 'vitest';
import { AssetSummarySchema, AssetDetailSchema } from '../../api/schemas';
import { mockAssets } from '@/mocks/data/assets';
import { mockAssetDetails } from '@/mocks/data/assetDetails';

describe('Asset schemas', () => {
  it('parses asset summary mock data', () => {
    const parsed = AssetSummarySchema.parse(mockAssets);
    expect(parsed.items.length).toBeGreaterThan(0);
    expect(parsed.totals.online).toBeDefined();
  });

  it('parses asset detail mock data', () => {
    const detail = Object.values(mockAssetDetails)[0];
    const parsed = AssetDetailSchema.parse(detail);
    expect(parsed.hostname).toBeDefined();
    expect(parsed.related_tasks.length).toBeGreaterThanOrEqual(0);
  });
});
