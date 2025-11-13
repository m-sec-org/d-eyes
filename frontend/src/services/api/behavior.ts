import httpClient from '../http';
import { AnomalyListResponseSchema, AnomalySchema, AnomalyGraphSchema } from './schemas';
import type { Anomaly, AnomalyGraph } from '../types';

export interface AnomalyFilters {
  status?: string;
  ioc?: string;
  agent_id?: string;
  min_score?: number;
  limit?: number;
}

export async function listAnomalies(filters?: AnomalyFilters): Promise<Anomaly[]> {
  const config = filters ? { params: filters } : undefined;
  const res = await httpClient.get('/anomalies', config);
  const parsed = AnomalyListResponseSchema.parse(res.data);
  return parsed.items;
}

export async function getAnomaly(id: string): Promise<Anomaly> {
  const res = await httpClient.get(`/anomalies/${id}`);
  return AnomalySchema.parse(res.data);
}

export async function getAnomalyGraph(id: string): Promise<AnomalyGraph> {
  const res = await httpClient.get(`/anomalies/${id}/graph`);
  return AnomalyGraphSchema.parse(res.data);
}
