import httpClient from '../http';
import { TemplateSchema } from './schemas';
import type { Template } from '../types';

export async function listTemplates(): Promise<Template[]> {
  const res = await httpClient.get('/task-templates');
  return TemplateSchema.array().parse(res.data);
}

export async function bulkDeployTemplates(ids: string[]): Promise<void> {
  await httpClient.post('/task-templates/deploy', { ids });
}

export async function bulkDeleteTemplates(ids: string[]): Promise<void> {
  await httpClient.post('/task-templates/delete', { ids });
}
