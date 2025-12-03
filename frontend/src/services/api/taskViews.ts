import httpClient from '../http';
import { TaskViewSchema } from './schemas';
import type { TaskView } from '../types';

export interface TaskViewListResponse {
  views: TaskView[];
}

export interface CreateTaskViewPayload {
  name: string;
  filters: Record<string, unknown>;
  page_size?: number;
  is_default?: boolean;
}

export async function listTaskViews(): Promise<TaskViewListResponse> {
  const res = await httpClient.get('/task-views');
  return {
    views: Array.isArray(res.data?.views)
      ? res.data.views.map((item: unknown) => TaskViewSchema.parse(item))
      : [],
  };
}

export async function createTaskView(payload: CreateTaskViewPayload): Promise<TaskView> {
  const res = await httpClient.post('/task-views', payload);
  return TaskViewSchema.parse(res.data);
}

export interface UpdateTaskViewPayload extends CreateTaskViewPayload {
  id: string;
}

export async function updateTaskView(payload: UpdateTaskViewPayload): Promise<TaskView> {
  const res = await httpClient.put(`/task-views/${payload.id}`, {
    name: payload.name,
    filters: payload.filters,
    page_size: payload.page_size,
    is_default: payload.is_default,
  });
  return TaskViewSchema.parse(res.data);
}

export async function deleteTaskView(id: string): Promise<void> {
  await httpClient.delete(`/task-views/${id}`);
}
