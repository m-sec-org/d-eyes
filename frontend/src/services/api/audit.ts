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

export async function listAuditEvents(): Promise<AuditListResponse> {
  const res = await httpClient.get('/audit/events');
  return AuditListSchema.parse(res.data);
}
