import httpClient from '../http';
import { TaskAuditReportSchema, TaskDetectReportSchema } from './schemas';
import type { TaskAuditReport, TaskDetectReport } from '../types';

export async function getTaskAuditReport(taskId: string): Promise<TaskAuditReport> {
  const res = await httpClient.get(`/tasks/${taskId}/audit/report`);
  return TaskAuditReportSchema.parse(res.data);
}

export async function getTaskDetectReport(taskId: string): Promise<TaskDetectReport> {
  const res = await httpClient.get(`/tasks/${taskId}/detect/report`);
  return TaskDetectReportSchema.parse(res.data);
}

