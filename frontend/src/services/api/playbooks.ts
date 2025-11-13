import httpClient from '../http';
import type { Playbook, PlaybookRun } from '../types';

export interface PlaybookPayload {
  name: string;
  description?: string;
  trigger: Record<string, unknown>;
  conditions?: string[];
  approvals?: Array<{ role: string; timeout?: number }>;
  actions: Array<Record<string, unknown>>;
  rollback?: Array<Record<string, unknown>>;
}

export async function createPlaybook(payload: PlaybookPayload): Promise<Playbook> {
  const res = await httpClient.post('/playbooks', payload);
  return res.data;
}

export async function listPlaybooks(limit = 50): Promise<Playbook[]> {
  const res = await httpClient.get('/playbooks', { params: { limit } });
  return res.data.items ?? [];
}

export async function getPlaybook(id: string): Promise<Playbook> {
  const res = await httpClient.get(`/playbooks/${id}`);
  return res.data;
}

export async function activatePlaybook(id: string, status = 'active'): Promise<Playbook> {
  const res = await httpClient.post(`/playbooks/${id}/activate`, { status });
  return res.data;
}

export async function runPlaybook(id: string, payload: { type: string; attributes?: Record<string, string>; data?: unknown }) {
  const res = await httpClient.post(`/playbooks/${id}/run`, {
    type: payload.type,
    attributes: payload.attributes,
    payload: payload.data,
  });
  return res.data;
}

export async function listPlaybookRuns(id: string, limit = 25): Promise<PlaybookRun[]> {
  const res = await httpClient.get(`/playbooks/${id}/runs`, { params: { limit } });
  return res.data.items ?? [];
}
