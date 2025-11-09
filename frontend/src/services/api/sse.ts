import { MockTaskEventSource } from '@/mocks/mockEventSource';

const STREAM_PATH = import.meta.env.VITE_WS_BASE_URL ?? '/api/v1/tasks/stream';
const USE_MOCK_SSE = import.meta.env.VITE_USE_MOCK_SSE !== 'false';

export function createTaskEventStream(channel?: string): EventSource {
  if (USE_MOCK_SSE) {
    return new MockTaskEventSource() as unknown as EventSource;
  }
  const url = new URL(STREAM_PATH, window.location.origin);
  if (channel) {
    url.searchParams.set('channel', channel);
  }
  return new EventSource(url.toString(), { withCredentials: true });
}
