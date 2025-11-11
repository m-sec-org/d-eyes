import httpClient from '../http';
import { z } from 'zod';

const AgentSchema = z.object({
  id: z.string(),
  name: z.string().optional().nullable(),
  status: z.string(),
  platform: z.string().optional().nullable(),
  version: z.string().optional().nullable(),
  capabilities: z.array(z.string()).default([]),
  labels: z.record(z.string()).optional(),
  last_heartbeat: z.string().optional().nullable(),
});

export type Agent = z.infer<typeof AgentSchema>;

export async function listAgents(params?: { status?: string; capability?: string; tag?: string }): Promise<Agent[]> {
  const res = await httpClient.get('/agents', { params });
  return z.array(AgentSchema).parse(res.data ?? []);
}

export async function updateAgentLabels(agentId: string, labels: Record<string, string>) {
  await httpClient.patch(`/agents/${agentId}/labels`, { labels });
}
