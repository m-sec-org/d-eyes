import { z } from 'zod';

import httpClient from '../http';
import { TaskVisualSchema } from './schemas';
import type { TaskVisual } from '../types';

const TaskVisualListSchema = z.object({
  items: z.array(TaskVisualSchema),
});

export async function fetchTaskVisuals(taskId: string, visualType?: string): Promise<TaskVisual[]> {
  const res = await httpClient.get(`/tasks/${taskId}/visuals`, {
    params: visualType ? { type: visualType } : undefined,
  });
  const data = TaskVisualListSchema.safeParse(res.data);
  if (data.success) {
    return data.data.items;
  }
  // fallback to parsing as an array for backwards compatibility
  const raw = z.array(TaskVisualSchema).safeParse(res.data);
  return raw.success ? raw.data : [];
}
