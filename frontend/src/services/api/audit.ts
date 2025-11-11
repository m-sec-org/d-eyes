import httpClient from '../http';
import { z } from 'zod';
import { AuditEventSchema } from './schemas';
import type { AuditEvent } from '../types';

export interface AuditListResponse {
  items: AuditEvent[];
}

const AuditListSchema = z
  .union([z.object({ items: AuditEventSchema.array() }), AuditEventSchema.array()])
  .transform((payload) => ('items' in payload ? payload : { items: payload }));

export interface AuditFilter {
  actor?: string;
  resource?: string;
  action?: string;
  limit?: number;
}

export async function listAuditEvents(filter?: AuditFilter): Promise<AuditListResponse> {
  const config = filter ? { params: filter } : undefined;
  const res = await httpClient.get('/audit/events', config);
  return AuditListSchema.parse(res.data);
}
