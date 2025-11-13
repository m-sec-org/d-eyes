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
  TaskProfileSchema,
  TaskProfileParameterSchema,
  TaskTypeCatalogSchema,
  TaskVisualSchema,
  BASScenarioSchema,
  BASScenarioStepSchema,
  BASResourceLimitSchema,
  BASExecutionPlanSchema,
  BASApprovalRuleSchema,
  BASRunReportSchema,
  BASRunStepSchema,
  ThreatIntelVerdictSchema,
  ThreatIntelIndicatorSchema,
  ThreatIntelLookupResponseSchema,
  ThreatIntelSampleSchema,
  ThreatIntelJobSchema,
  ThreatIntelEventSchema,
  AnomalySchema,
  AnomalyGraphSchema,
  AnomalyEventSchema,
  PlaybookSchema,
  PlaybookRunSchema,
  ComplianceFrameworkSchema,
  ComplianceControlSchema,
  ComplianceFindingSchema,
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
export type TaskProfile = z.infer<typeof TaskProfileSchema>;
export type TaskProfileParameter = z.infer<typeof TaskProfileParameterSchema>;
export type TaskTypeDefinition = z.infer<typeof TaskTypeCatalogSchema>;
export type TaskVisual = z.infer<typeof TaskVisualSchema>;
export type BASScenario = z.infer<typeof BASScenarioSchema>;
export type BASScenarioStep = z.infer<typeof BASScenarioStepSchema>;
export type BASResourceLimit = z.infer<typeof BASResourceLimitSchema>;
export type BASExecutionPlan = z.infer<typeof BASExecutionPlanSchema>;
export type BASApprovalRule = z.infer<typeof BASApprovalRuleSchema>;
export type BASRunReport = z.infer<typeof BASRunReportSchema>;
export type BASRunStep = z.infer<typeof BASRunStepSchema>;
export type ThreatIntelVerdict = z.infer<typeof ThreatIntelVerdictSchema>;
export type ThreatIntelIndicator = z.infer<typeof ThreatIntelIndicatorSchema>;
export type ThreatIntelLookupResponse = z.infer<typeof ThreatIntelLookupResponseSchema>;
export type ThreatIntelSample = z.infer<typeof ThreatIntelSampleSchema>;
export type ThreatIntelJob = z.infer<typeof ThreatIntelJobSchema>;
export type ThreatIntelEvent = z.infer<typeof ThreatIntelEventSchema>;
export type Anomaly = z.infer<typeof AnomalySchema>;
export type AnomalyGraph = z.infer<typeof AnomalyGraphSchema>;
export type AnomalyEvent = z.infer<typeof AnomalyEventSchema>;
export type Playbook = z.infer<typeof PlaybookSchema>;
export type PlaybookRun = z.infer<typeof PlaybookRunSchema>;
export type ComplianceFramework = z.infer<typeof ComplianceFrameworkSchema>;
export type ComplianceControl = z.infer<typeof ComplianceControlSchema>;
export type ComplianceFinding = z.infer<typeof ComplianceFindingSchema>;
