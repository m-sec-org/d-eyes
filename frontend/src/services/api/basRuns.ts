import httpClient from '../http';
import { BASRunReportSchema } from './schemas';
import type { BASRunReport } from '../types';

export async function getBASReport(taskId: string): Promise<BASRunReport> {
  const res = await httpClient.get(`/tasks/${taskId}/bas/report`);
  return BASRunReportSchema.parse(res.data);
}
