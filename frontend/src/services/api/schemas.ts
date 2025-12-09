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

export const TaskListSummarySchema = z.object({
  total: z.number(),
  by_status: z.record(z.number()).optional(),
});

export const TaskListFiltersSchema = z.object({
  status: z.array(z.string()).optional(),
  search: z.string().optional(),
  view_id: z.string().optional(),
});

export const TaskListResponseSchema = z.object({
  data: z.array(TaskSchema),
  page_size: z.number(),
  next_cursor: z.string().optional().nullable(),
  filters: TaskListFiltersSchema.optional(),
  summary: TaskListSummarySchema.optional(),
});

export const TaskViewSchema = z.object({
  id: z.string().uuid(),
  name: z.string(),
  filters: z.record(z.any()),
  page_size: z.number(),
  is_default: z.boolean().optional(),
  created_at: z.string().datetime(),
  updated_at: z.string().datetime(),
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
  bas_queue_depth: z.number().optional(),
  progress: z.number().optional(),
  message: z.string().optional(),
  action: z.string().optional(),
  actor: z.string().optional(),
  severity: z.string().optional(),
  updated_at: z.string().datetime(),
});

export const SystemEventRecordSchema = z.object({
  id: z.string().uuid(),
  agent_id: z.string().uuid(),
  agent_name: z.string(),
  collector: z.string().optional().nullable(),
  collector_kind: z.string().optional().nullable(),
  event_type: z.string(),
  source: z.string().optional().nullable(),
  priority: z.string().optional().nullable(),
  storage_tier: z.string().optional().nullable(),
  timestamp: z.string().datetime(),
  sequence: z.number().nonnegative(),
  payload: z.any().optional(),
  metadata: z.record(z.string()).optional(),
  tags: z.record(z.string()).optional(),
  raw: z.any().optional(),
  received_at: z.string().datetime(),
});

export const SystemEventCursorSchema = z.object({
  received_at: z.string().datetime(),
  id: z.string().uuid(),
});

export const SystemEventListResponseSchema = z.object({
  items: z.array(SystemEventRecordSchema),
  next_cursor: SystemEventCursorSchema.optional().nullable(),
});

export const SystemEventAggregatesSchema = z.object({
  total: z.number(),
  by_event_type: z.record(z.number()).optional(),
  by_source: z.record(z.number()).optional(),
});

export const DetectionStreamEventSchema = TaskEventSchema.extend({
  event: z.string(),
  metadata: z.record(z.string()).optional(),
});

export const CollectorConfigSchema = z.object({
  id: z.string(),
  name: z.string(),
  kind: z.string(),
  region: z.string().optional().nullable(),
  priority: z.string().optional().nullable(),
  storage_tier: z.string(),
  sampling_rate: z.number().min(0).max(1),
  lag_threshold: z.number().nonnegative().optional().default(0),
  enabled: z.boolean().default(true),
  status: z.string().optional().nullable(),
  last_heartbeat: z.string().datetime().optional().nullable(),
  description: z.string().optional().nullable(),
  tags: z.array(z.string()).optional(),
});

const TrendMetricSchema = z.object({
  delta: z.number(),
  trend: z.enum(['up', 'down', 'flat']).optional(),
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
  trends: z
    .object({
      period: z.string().optional(),
      totals: z.record(TrendMetricSchema).optional(),
      status: z.record(TrendMetricSchema).optional(),
    })
    .optional(),
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

export const TaskProfileParameterSchema = z.object({
  key: z.string(),
  label: z.string(),
  type: z.enum(['string', 'number', 'boolean', 'enum', 'multiselect', 'string_list', 'cidr_list']),
  required: z.boolean().optional(),
  options: z.array(z.string()).optional(),
  pattern: z.string().optional(),
  format: z.string().optional(),
  min: z.number().optional(),
  max: z.number().optional(),
  default: z.any().optional(),
  hint: z.string().optional(),
});

export const TaskProfileSchema = z.object({
  id: z.string(),
  task_type: z.string(),
  display_name: z.string(),
  version: z.string(),
  description: z.string().optional().nullable(),
  owner: z.string().optional().nullable(),
  schema: z.object({
    defaults: z.record(z.any()).optional(),
    parameters: z.array(TaskProfileParameterSchema),
    constraints: z
      .array(
        z.object({
          expression: z.string(),
          message: z.string(),
        })
      )
      .optional(),
  }),
  created_at: z.string().datetime().optional(),
  updated_at: z.string().datetime().optional(),
});

export const TaskTypeCatalogSchema = z.object({
  name: z.string(),
  display_name: z.string(),
  description: z.string().optional().nullable(),
  capabilities: z.array(z.string()).optional(),
  created_at: z.string().datetime().optional(),
  updated_at: z.string().datetime().optional(),
});

export const TaskVisualSchema = z.object({
  task_id: z.string().uuid(),
  task_type: z.string(),
  visual_type: z.string(),
  generated_at: z.string().datetime(),
  payload: z.record(z.any()),
});

export const BASResourceLimitSchema = z.object({
  max_targets: z.number().optional(),
  max_parallel_steps: z.number().optional(),
  max_duration_minutes: z.number().optional(),
  max_cpu_percent: z.number().optional(),
});

export const BASScenarioStepSchema = z.object({
  id: z.string(),
  name: z.string(),
  action: z.string(),
  order: z.number(),
  args: z.record(z.any()).optional(),
  timeout_seconds: z.number().optional(),
  require_sandbox: z.boolean().optional(),
  agent_profile: z.string().optional().nullable(),
  capabilities: z.array(z.string()).optional(),
  depends_on: z.array(z.string()).optional(),
  parallel_group: z.string().optional().nullable(),
  severity: z.string().optional().nullable(),
  expect_artifacts: z.boolean().optional(),
  telemetry_hints: z.record(z.string()).optional(),
  execution_context: z.record(z.any()).optional(),
});

export const BASApprovalRuleSchema = z.object({
  role: z.string(),
  timeout_seconds: z.number().optional(),
});

export const BASExecutionPlanSchema = z.object({
  mode: z.string().optional(),
  max_parallel: z.number().optional(),
  retry_limit: z.number().optional(),
  step_timeout_seconds: z.number().optional(),
  cross_agent: z.boolean().optional(),
});

export const BASScenarioSchema = z.object({
  id: z.string().uuid(),
  name: z.string(),
  description: z.string().optional().nullable(),
  tags: z.array(z.string()).optional(),
  status: z.enum(['draft', 'pending', 'approved', 'active', 'disabled']),
  version: z.number().optional(),
  steps: z.array(BASScenarioStepSchema),
  resource_limits: BASResourceLimitSchema,
  network_boundaries: z.array(z.string()).optional(),
  requires_approval: z.boolean().optional(),
  approval_policy: z.array(BASApprovalRuleSchema).optional(),
  execution_plan: BASExecutionPlanSchema.optional(),
  dependencies: z.array(z.string().uuid()).optional(),
  required_labels: z.array(z.string()).optional(),
  approval: z
    .object({
      approved_by: z.string().optional().nullable(),
      approved_at: z.string().datetime().optional().nullable(),
      notes: z.string().optional().nullable(),
    })
    .optional(),
  created_by: z.string().optional().nullable(),
  updated_by: z.string().optional().nullable(),
  created_at: z.string().datetime().optional(),
  updated_at: z.string().datetime().optional(),
  published_at: z.string().datetime().optional().nullable(),
});

export const BASRunStepSchema = z.object({
  id: z.string(),
  name: z.string(),
  status: z.string(),
  exit_code: z.number(),
  message: z.string().optional().nullable(),
  stdout: z.string().optional().nullable(),
  stderr: z.string().optional().nullable(),
  sandbox: z.boolean().optional(),
  started_at: z.string().datetime().optional().nullable(),
  ended_at: z.string().datetime().optional().nullable(),
});

export const BASRunReportSchema = z.object({
  task_id: z.string(),
  task_type: z.string(),
  profile: z.string().optional().nullable(),
  run_id: z.string(),
  agent_id: z.string(),
  task_status: z.string(),
  scenario_id: z.string().optional().nullable(),
  scenario_name: z.string().optional().nullable(),
  scenario_tags: z.array(z.string()).optional(),
  description: z.string().optional().nullable(),
  steps: z.array(BASRunStepSchema).default([]),
  summary: z.object({
    total: z.number(),
    success: z.number(),
    failed: z.number(),
    skipped: z.number(),
  }),
  result: z.record(z.any()).optional(),
  outputs: z
    .array(
      z.object({
        path: z.string(),
        label: z.string().optional().nullable(),
      })
    )
    .optional(),
  run_metadata: z.record(z.string()).optional(),
  exit_code: z.number().optional(),
  error_code: z.string().optional(),
  failed_steps: z.array(z.string()).optional(),
  completed_at: z.string().datetime().optional().nullable(),
  expires_at: z.string().datetime().optional().nullable(),
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

export const ThreatIntelVerdictSchema = z.object({
  id: z.string(),
  indicator: z.string(),
  kind: z.string().optional().nullable(),
  source: z.string(),
  classification: z.string().optional().nullable(),
  confidence: z.string().optional().nullable(),
  retrieved_at: z.string().datetime(),
  expires_at: z.string().datetime().optional().nullable(),
  metadata: z.record(z.string()).optional(),
});

export const ThreatIntelIndicatorSchema = z.object({
  indicator: z.string(),
  verdicts: z.array(ThreatIntelVerdictSchema).default([]),
});

export const ThreatIntelLookupResponseSchema = z.object({
  job_ids: z.array(z.string().uuid()),
  cached: z.boolean().optional(),
  verdicts: z.array(ThreatIntelVerdictSchema).optional().default([]),
});

export const ThreatIntelJobSchema = z.object({
  id: z.string().uuid(),
  sample_id: z.string().uuid().optional().nullable(),
  indicator: z.string().optional().nullable(),
  kind: z.string().optional().nullable(),
  source: z.string(),
  status: z.string(),
  attempt: z.number().optional(),
  error: z.string().optional().nullable(),
  error_code: z.string().optional().nullable(),
  next_run_at: z.string().datetime().optional().nullable(),
  task_run_id: z.string().uuid().optional().nullable(),
  agent_id: z.string().uuid().optional().nullable(),
  updated_at: z.string().datetime(),
  last_transition_at: z.string().datetime().optional().nullable(),
  artifact_ids: z.array(z.string().uuid()).optional(),
  metadata: z.record(z.string()).optional(),
  summary: z.record(z.any()).optional(),
});

const ArtifactDetailSchema = z.object({
  id: z.string().uuid(),
  sha256: z.string().optional().nullable(),
  mime_type: z.string().optional().nullable(),
  quarantine_path: z.string().optional().nullable(),
});

export const ThreatIntelSampleSchema = z.object({
  id: z.string().uuid(),
  indicator: z.string().optional().nullable(),
  hash: z.string().optional().nullable(),
  filename: z.string().optional().nullable(),
  size: z.number().optional(),
  status: z.string(),
  artifact_ids: z.array(z.string().uuid()).optional(),
  artifact_details: z.array(ArtifactDetailSchema).optional().default([]),
  task_run_id: z.string().uuid(),
  agent_id: z.string().uuid(),
  source: z.string().optional().nullable(),
  classification: z.string().optional().nullable(),
  metadata: z.record(z.string()).optional(),
  last_error: z.string().optional().nullable(),
  last_error_code: z.string().optional().nullable(),
  created_at: z.string().datetime(),
  updated_at: z.string().datetime(),
  job_statuses: z.record(z.string()).optional(),
  jobs: z.array(ThreatIntelJobSchema).default([]),
});

export const ThreatIntelEventSchema = z.object({
  event: z.string(),
  sample_id: z.string().optional(),
  job_id: z.string().optional(),
  indicator: z.string().optional(),
  source: z.string().optional(),
  status: z.string().optional(),
  classification: z.string().optional(),
  confidence: z.string().optional(),
  message: z.string().optional(),
  metadata: z.record(z.string()).optional(),
  timestamp: z.string().datetime(),
});

export const AnomalySchema = z.object({
  id: z.string().uuid(),
  agent_id: z.string().uuid().nullable().optional(),
  task_id: z.string().uuid().nullable().optional(),
  ioc: z.string().nullable().optional(),
  entities: z.array(z.string()).default([]),
  severity: z.string(),
  score: z.number(),
  summary: z.record(z.any()).optional(),
  status: z.string(),
  created_at: z.string().datetime(),
  updated_at: z.string().datetime(),
});

export const AnomalyListResponseSchema = z.object({
  items: z.array(AnomalySchema),
});

export const BehaviorGraphNodeSchema = z.object({
  id: z.string().uuid(),
  anomaly_id: z.string().uuid(),
  type: z.string(),
  label: z.string().nullable().optional(),
  properties: z.record(z.any()).optional(),
  created_at: z.string().datetime(),
});

export const BehaviorGraphEdgeSchema = z.object({
  id: z.string().uuid(),
  anomaly_id: z.string().uuid(),
  source_node: z.string().uuid(),
  target_node: z.string().uuid(),
  type: z.string(),
  properties: z.record(z.any()).optional(),
  created_at: z.string().datetime(),
});

export const AnomalyGraphSchema = z.object({
  nodes: z.array(BehaviorGraphNodeSchema).default([]),
  edges: z.array(BehaviorGraphEdgeSchema).default([]),
});

export const AnomalyEventSchema = z.object({
  event: z.string(),
  anomaly: AnomalySchema.optional(),
  graph: AnomalyGraphSchema.optional(),
  timestamp: z.string().datetime(),
});

export const PlaybookTriggerSchema = z.object({
  type: z.string(),
  filter: z.record(z.string()).optional(),
});

export const PlaybookApprovalSchema = z.object({
  role: z.string(),
  timeout: z.number().optional().nullable(),
});

export const PlaybookActionSchema = z.object({
  type: z.string(),
  target: z.string().optional().nullable(),
  task_type: z.string().optional().nullable(),
  payload: z.record(z.any()).optional().nullable(),
  command: z.string().optional().nullable(),
  args: z.record(z.any()).optional().nullable(),
  metadata: z.record(z.string()).optional().nullable(),
});

export const PlaybookSchema = z.object({
  id: z.string().uuid(),
  name: z.string(),
  description: z.string().optional().nullable(),
  trigger: PlaybookTriggerSchema,
  conditions: z.array(z.string()).optional().nullable(),
  approvals: z.array(PlaybookApprovalSchema).optional().nullable(),
  actions: z.array(PlaybookActionSchema),
  rollback: z.array(PlaybookActionSchema).optional().nullable(),
  status: z.string(),
  version: z.number().optional(),
  created_by: z.string().optional().nullable(),
  updated_by: z.string().optional().nullable(),
  approved_by: z.string().optional().nullable(),
  created_at: z.string().datetime().optional(),
  updated_at: z.string().datetime().optional(),
  last_run_at: z.string().datetime().optional().nullable(),
});

export const PlaybookRunStepSchema = z.object({
  name: z.string(),
  type: z.string(),
  status: z.string(),
  started_at: z.string().datetime(),
  completed_at: z.string().datetime().optional().nullable(),
  error: z.string().optional().nullable(),
});

export const PlaybookRunSchema = z.object({
  id: z.string().uuid(),
  playbook_id: z.string().uuid(),
  status: z.string(),
  trigger_type: z.string().optional().nullable(),
  created_at: z.string().datetime(),
  updated_at: z.string().datetime(),
  completed_at: z.string().datetime().optional().nullable(),
  steps: z.array(PlaybookRunStepSchema).optional().nullable(),
});

export const ComplianceFrameworkSchema = z.object({
  id: z.string().uuid(),
  key: z.string(),
  title: z.string(),
  version: z.string().optional().nullable(),
  description: z.string().optional().nullable(),
  created_at: z.string().datetime().optional(),
  updated_at: z.string().datetime().optional(),
});

export const ComplianceControlSchema = z.object({
  id: z.string().uuid(),
  framework_id: z.string().uuid(),
  code: z.string(),
  title: z.string(),
  severity: z.string(),
  description: z.string().optional().nullable(),
  references: z.record(z.string()).optional().nullable(),
  created_at: z.string().datetime().optional(),
  updated_at: z.string().datetime().optional(),
});

export const RemediationNoteSchema = z.object({
  author: z.string(),
  note: z.string(),
  timestamp: z.string().datetime(),
});

export const ComplianceFindingSchema = z.object({
  id: z.string().uuid(),
  framework_id: z.string().uuid(),
  control_id: z.string().uuid(),
  asset_ref: z.string().optional().nullable(),
  status: z.string(),
  evidence: z.record(z.string()).optional().nullable(),
  remediation_logs: z.array(RemediationNoteSchema).optional().nullable(),
  created_at: z.string().datetime(),
  updated_at: z.string().datetime(),
});
