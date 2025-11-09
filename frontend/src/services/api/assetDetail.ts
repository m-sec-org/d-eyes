import httpClient from '../http';
import { AssetDetailSchema } from './schemas';

export async function getAssetDetail(id: string) {
  const res = await httpClient.get(`/assets/${id}`);
  return AssetDetailSchema.parse(res.data);
}

export async function batchTagAssets(ids: string[], tag: string) {
  const res = await httpClient.post('/assets/batch-tag', { ids, tag });
  return res.data as { ids: string[]; tag: string };
}
