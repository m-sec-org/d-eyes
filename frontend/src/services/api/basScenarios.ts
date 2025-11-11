import { z } from 'zod';

import httpClient from '../http';
import { BASScenarioSchema } from './schemas';
import type { BASScenario } from '../types';

const BASScenarioListSchema = z.array(BASScenarioSchema);

export async function listBASScenarios(): Promise<BASScenario[]> {
  const res = await httpClient.get('/bas-scenarios');
  return BASScenarioListSchema.parse(res.data ?? []);
}

export async function createBASScenario(payload: Partial<BASScenario>): Promise<BASScenario> {
  const res = await httpClient.post('/bas-scenarios', payload);
  return BASScenarioSchema.parse(res.data);
}

export async function updateBASScenario(id: string, payload: Partial<BASScenario>): Promise<BASScenario> {
  const res = await httpClient.put(`/bas-scenarios/${id}`, payload);
  return BASScenarioSchema.parse(res.data);
}

export async function approveBASScenario(id: string, approver: string, notes?: string): Promise<BASScenario> {
  const res = await httpClient.post(`/bas-scenarios/${id}/approve`, { approved_by: approver, notes });
  return BASScenarioSchema.parse(res.data);
}

export async function activateBASScenario(id: string): Promise<BASScenario> {
  const res = await httpClient.post(`/bas-scenarios/${id}/activate`);
  return BASScenarioSchema.parse(res.data);
}

export async function deactivateBASScenario(id: string): Promise<BASScenario> {
  const res = await httpClient.post(`/bas-scenarios/${id}/deactivate`);
  return BASScenarioSchema.parse(res.data);
}
