import httpClient from '../http';
import { z } from 'zod';

const RbacPolicySchema = z.object({
  role: z.string(),
  permissions: z.array(z.string()),
});

export type RbacPolicy = z.infer<typeof RbacPolicySchema>;

export async function listRbacPolicies(): Promise<RbacPolicy[]> {
  const res = await httpClient.get('/rbac/policies');
  return z.object({ policies: z.array(RbacPolicySchema) }).parse(res.data).policies;
}
