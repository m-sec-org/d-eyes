import httpClient from '../http';

export interface QueueSummary {
  queue_depth: number;
  bas_queue_depth: number;
  in_flight: number;
  bas_in_flight: number;
  status_counts?: Record<string, number>;
  updated_at: string;
}

export async function fetchQueueSummary(): Promise<QueueSummary> {
  const res = await httpClient.get('/queues/summary');
  return res.data as QueueSummary;
}
