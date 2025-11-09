import httpClient from '../http';
import { TaskListResponseSchema } from './schemas';
import type { TaskListResponse } from '../types';

export interface TaskFilters {
  status?: string;
  limit?: number;
}

export async function listTasks(filters?: TaskFilters): Promise<TaskListResponse> {
  const res = await httpClient.get('/tasks', { params: filters });
  return TaskListResponseSchema.parse(res.data);
}
