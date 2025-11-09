import { z } from 'zod';

export const TaskRunSchema = z.object({
  id: z.string().uuid(),
  agent_id: z.string().uuid(),
  status: z.enum(['pending', 'leased', 'running', 'succeeded', 'failed', 'canceled']),
  started_at: z.string().datetime().optional().nullable(),
  finished_at: z.string().datetime().optional().nullable(),
  summary: z.record(z.any()).optional(),
  metadata: z.record(z.string()).optional(),
  exit_code: z.number().optional(),
  error_code: z.string().optional(),
  expires_at: z.string().datetime().optional().nullable(),
});

export const TaskSchema = z.object({
  id: z.string().uuid(),
  type: z.string(),
  profile: z.string().nullable().optional(),
  priority: z.number(),
  status: z.string(),
  retry_count: z.number().optional().default(0),
  metadata: z.record(z.string()).optional(),
  created_by: z.string().optional(),
  created_at: z.string().datetime(),
  updated_at: z.string().datetime(),
  last_run: TaskRunSchema.optional().nullable(),
});

export const TaskListResponseSchema = z.object({
  data: z.array(TaskSchema),
});

export const TaskEventSchema = z.object({
  event: z.string(),
  task_id: z.string().uuid(),
  task_type: z.string(),
  status: z.string(),
  agent_id: z.string().uuid().optional(),
  metadata: z.record(z.string()).optional(),
  queue_depth: z.number().optional(),
  in_flight: z.number().optional(),
  bas_in_flight: z.number().optional(),
  updated_at: z.string().datetime(),
});

export const ReportSummarySchema = z.object({
  items: z.array(
    z.object({
      result_id: z.string(),
      task_id: z.string(),
      task_type: z.string(),
      status: z.string(),
      scenario_id: z.string().optional().nullable(),
      scenario_name: z.string().optional().nullable(),
      metadata: z.record(z.string()).optional(),
      completed_at: z.string().datetime(),
    })
  ),
  totals: z.record(z.number()),
  status: z.record(z.number()),
});

export const TemplateSchema = z.object({
  id: z.string().uuid(),
  name: z.string(),
  description: z.string().optional().nullable(),
  task_type: z.string(),
  profile: z.string().nullable().optional(),
  flags: z.record(z.any()).optional(),
  metadata: z.record(z.string()).optional(),
  targets: z.array(z.string()).optional(),
  priority: z.number().optional(),
  created_by: z.string().optional(),
  schedule: z
    .object({
      enabled: z.boolean(),
      interval_minutes: z.number().optional(),
      next_run: z.string().datetime().optional().nullable(),
    })
    .optional()
    .nullable(),
});

export const AuditEventSchema = z.object({
  id: z.string(),
  timestamp: z.string().datetime(),
  actor: z.string(),
  role: z.string(),
  action: z.string(),
  resource: z.string(),
  result: z.string().optional(),
  metadata: z.record(z.any()).optional(),
});

export const AuthSessionSchema = z.object({
  token: z.string(),
  refresh_token: z.string(),
  expires_in: z.number(), // seconds
  user: z.object({
    username: z.string(),
    display_name: z.string(),
    role: z.enum(['operator', 'auditor', 'admin']),
    capabilities: z.array(z.string()).optional(),
  }),
});

export const AssetSummarySchema = z.object({
  items: z.array(
    z.object({
      id: z.string(),
      hostname: z.string(),
      ip: z.string(),
      status: z.enum(['online', 'offline', 'unknown']),
      tags: z.array(z.string()).default([]),
      risk_level: z.enum(['low', 'medium', 'high']),
      last_seen: z.string().datetime(),
    })
  ),
  totals: z.object({
    online: z.number(),
    offline: z.number(),
    critical: z.number(),
  }),
});

export const AssetDetailSchema = z.object({
  id: z.string(),
  hostname: z.string(),
  ip: z.string(),
  status: z.enum(['online', 'offline', 'unknown']),
  tags: z.array(z.string()).default([]),
  risk_level: z.enum(['low', 'medium', 'high']),
  platform: z.string().optional().nullable(),
  owner: z.string().optional().nullable(),
  last_seen: z.string().datetime(),
  related_tasks: z
    .array(
      z.object({
        id: z.string(),
        type: z.string(),
        status: z.string(),
        completed_at: z.string().datetime().optional().nullable(),
      })
    )
    .default([]),
  related_risks: z
    .array(
      z.object({
        id: z.string(),
        severity: z.enum(['low', 'medium', 'high']),
        summary: z.string(),
        timestamp: z.string().datetime(),
      })
    )
    .default([]),
  operations: z
    .array(
      z.object({
        actor: z.string(),
        action: z.string(),
        timestamp: z.string().datetime(),
      })
    )
    .default([]),
});
