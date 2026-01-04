import httpClient from '../http';
import { TaskSchema } from './schemas';
import type { Task } from '../types';

export interface CreateTaskPayload {
  type: string;
  profile?: string;
  priority?: number;
  metadata?: Record<string, string>;
  payload?: Record<string, unknown>;
  created_by?: string;
}

export async function createTask(payload: CreateTaskPayload): Promise<{ id: string }> {
  const nextPayload: CreateTaskPayload = { ...payload };
  const metadata = payload.metadata ? { ...payload.metadata } : undefined;
  if (!metadata || !('required_capabilities' in metadata)) {
    nextPayload.metadata = {
      ...(metadata ?? {}),
      required_capabilities: payload.type,
    };
  }
  const res = await httpClient.post('/tasks', nextPayload);
  return res.data;
}

export async function retryTask(taskId: string): Promise<Task> {
  const res = await httpClient.post(`/tasks/${taskId}/retry`);
  return TaskSchema.parse(res.data);
}

export async function cancelTask(taskId: string): Promise<Task> {
  const res = await httpClient.post(`/tasks/${taskId}/cancel`);
  return TaskSchema.parse(res.data);
}

export async function performTaskAction(taskId: string, action: 'pause' | 'resume' | 'terminate' | 'ack', reason?: string) {
  await httpClient.post(`/tasks/${taskId}/actions`, { action, reason });
}
