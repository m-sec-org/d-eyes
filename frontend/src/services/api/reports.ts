import httpClient from '../http';
import { ReportSummarySchema } from './schemas';
import type { ReportSummary } from '../types';

export async function getSummary(taskType?: string): Promise<ReportSummary> {
  const res = await httpClient.get('/reports/summary', {
    params: taskType ? { type: taskType } : undefined,
  });
  return ReportSummarySchema.parse(res.data);
}
