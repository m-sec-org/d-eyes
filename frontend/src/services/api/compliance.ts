import httpClient from '../http';
import { ComplianceFrameworkSchema, ComplianceControlSchema, ComplianceFindingSchema } from './schemas';
import type { ComplianceFramework, ComplianceControl, ComplianceFinding } from '../types';

export async function listComplianceFrameworks(): Promise<ComplianceFramework[]> {
  const res = await httpClient.get('/compliance/frameworks');
  const items = Array.isArray(res.data?.items) ? res.data.items : [];
  return items.map((item: unknown) => ComplianceFrameworkSchema.parse(item));
}

export async function listComplianceControls(frameworkId: string): Promise<ComplianceControl[]> {
  const res = await httpClient.get(`/compliance/frameworks/${frameworkId}/controls`);
  const items = Array.isArray(res.data?.items) ? res.data.items : [];
  return items.map((item: unknown) => ComplianceControlSchema.parse(item));
}

export async function listComplianceGaps(params: { framework_id?: string; status?: string }): Promise<ComplianceFinding[]> {
  const res = await httpClient.get('/compliance/gaps', { params });
  const items = Array.isArray(res.data?.items) ? res.data.items : [];
  return items.map((item: unknown) => ComplianceFindingSchema.parse(item));
}

export async function addRemediationNote(findingId: string, note: string, status?: string): Promise<ComplianceFinding> {
  const res = await httpClient.post(`/compliance/findings/${findingId}/remediation`, { note, status });
  return ComplianceFindingSchema.parse(res.data);
}
