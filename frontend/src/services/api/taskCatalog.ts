import { z } from 'zod';

import httpClient from '../http';
import { TaskProfileSchema, TaskTypeCatalogSchema } from './schemas';
import type { TaskProfile, TaskTypeDefinition } from '../types';

const TaskTypeListSchema = z.array(TaskTypeCatalogSchema);
const TaskProfileListSchema = z.array(TaskProfileSchema);

export async function listTaskTypes(): Promise<TaskTypeDefinition[]> {
  const res = await httpClient.get('/task-types');
  return TaskTypeListSchema.parse(res.data ?? []);
}

export async function listTaskProfiles(taskType?: string): Promise<TaskProfile[]> {
  const res = await httpClient.get('/task-profiles', {
    params: taskType ? { task_type: taskType } : undefined,
  });
  return TaskProfileListSchema.parse(res.data ?? []);
}
