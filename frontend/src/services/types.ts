import { z } from 'zod';
import {
  AuditEventSchema,
  AuthSessionSchema,
  ReportSummarySchema,
  TaskEventSchema,
  TaskListResponseSchema,
  TaskSchema,
  TemplateSchema,
  AssetSummarySchema,
  AssetDetailSchema,
} from './api/schemas';

export type Task = z.infer<typeof TaskSchema>;
export type TaskListResponse = z.infer<typeof TaskListResponseSchema>;
export type TaskEvent = z.infer<typeof TaskEventSchema>;
export type ReportSummary = z.infer<typeof ReportSummarySchema>;
export type Template = z.infer<typeof TemplateSchema>;
export type AuditEvent = z.infer<typeof AuditEventSchema>;
export type AuthSession = z.infer<typeof AuthSessionSchema>;
export type AssetSummary = z.infer<typeof AssetSummarySchema>;
export type AssetDetail = z.infer<typeof AssetDetailSchema>;
