import httpClient from '../http';
import { TaskListResponseSchema } from './schemas';
import type { TaskListResponse } from '../types';

export interface TaskListQuery {
  statuses?: string[];
  search?: string;
  limit?: number;
  cursor?: string;
  view_id?: string;
}

export async function listTasks(query?: TaskListQuery): Promise<TaskListResponse> {
  const params: Record<string, string | number> = {};
  if (query?.statuses && query.statuses.length > 0) {
    params.status = query.statuses.join(',');
  }
  if (query?.search) {
    params.search = query.search;
  }
  if (query?.limit) {
    params.limit = query.limit;
  }
  if (query?.cursor) {
    params.cursor = query.cursor;
  }
  if (query?.view_id) {
    params.view_id = query.view_id;
  }
  const res = await httpClient.get('/tasks', Object.keys(params).length ? { params } : undefined);
  return TaskListResponseSchema.parse(res.data);
}
