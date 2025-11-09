import httpClient from '../http';
import { AssetSummarySchema } from './schemas';
import type { AssetSummary } from '../types';

export async function listAssets(): Promise<AssetSummary> {
  const res = await httpClient.get('/assets');
  return AssetSummarySchema.parse(res.data);
}
