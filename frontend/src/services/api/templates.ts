import httpClient from '../http';
import { TemplateSchema } from './schemas';
import type { Template } from '../types';

export async function listTemplates(): Promise<Template[]> {
  const res = await httpClient.get('/task-templates');
  return TemplateSchema.array().parse(res.data);
}
