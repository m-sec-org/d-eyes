import httpClient from '../http';
import { z } from 'zod';

const ReportTemplateSchema = z.object({
  id: z.string().uuid(),
  name: z.string(),
  description: z.string().optional().nullable(),
  format: z.string(),
  body: z.string(),
  owner: z.string().optional().nullable(),
  created_at: z.string().datetime().optional().nullable(),
  updated_at: z.string().datetime().optional().nullable(),
});

export type ReportTemplate = z.infer<typeof ReportTemplateSchema>;

export async function listReportTemplates(): Promise<ReportTemplate[]> {
  const res = await httpClient.get('/reports/templates');
  return z.array(ReportTemplateSchema).parse(res.data ?? []);
}

export async function createReportTemplate(payload: Partial<ReportTemplate>): Promise<ReportTemplate> {
  const res = await httpClient.post('/reports/templates', payload);
  return ReportTemplateSchema.parse(res.data);
}

export async function updateReportTemplate(id: string, payload: Partial<ReportTemplate>): Promise<ReportTemplate> {
  const res = await httpClient.put(`/reports/templates/${id}`, payload);
  return ReportTemplateSchema.parse(res.data);
}

export async function deleteReportTemplate(id: string): Promise<void> {
  await httpClient.delete(`/reports/templates/${id}`);
}

export async function generateReport(params: { taskId: string; templateId: string; format: string }): Promise<Blob> {
  const res = await httpClient.post(
    '/reports/generate',
    { task_id: params.taskId, template_id: params.templateId, format: params.format },
    { responseType: 'blob' }
  );
  return res.data as Blob;
}
