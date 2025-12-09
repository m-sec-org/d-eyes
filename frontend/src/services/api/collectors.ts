import httpClient from '../http';
import { CollectorConfigSchema } from './schemas';
import type { CollectorConfig } from '../types';

export async function fetchCollectors(): Promise<CollectorConfig[]> {
  const res = await httpClient.get('/collectors');
  return CollectorConfigSchema.array().parse(res.data);
}

export async function updateCollectorConfig(
  collectorId: string,
  payload: Partial<Pick<CollectorConfig, 'priority' | 'storage_tier' | 'sampling_rate' | 'lag_threshold' | 'enabled'>>
): Promise<CollectorConfig> {
  const res = await httpClient.patch(`/collectors/${collectorId}`, payload);
  return CollectorConfigSchema.parse(res.data);
}
