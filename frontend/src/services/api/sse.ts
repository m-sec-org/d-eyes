import {
  MockTaskEventSource,
  MockThreatIntelEventSource,
  MockAnomalyEventSource,
  MockDetectionEventSource,
} from '@/mocks/mockEventSource';

const STREAM_PATH = import.meta.env.VITE_WS_BASE_URL ?? '/api/v1/tasks/stream';
const TI_STREAM_PATH = import.meta.env.VITE_THREAT_INTEL_STREAM_URL ?? '/api/v1/threat-intel/stream';
const ANOMALY_STREAM_PATH = import.meta.env.VITE_ANOMALY_STREAM_URL ?? '/api/v1/anomalies/stream';
const QUEUE_STREAM_PATH = import.meta.env.VITE_QUEUE_STREAM_URL ?? '/api/v1/queues/stream';
const DETECTION_STREAM_PATH = import.meta.env.VITE_DETECTION_STREAM_URL ?? '/api/v1/detections/stream';
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

export function createThreatIntelEventStream(): EventSource {
  if (USE_MOCK_SSE) {
    return new MockThreatIntelEventSource() as unknown as EventSource;
  }
  const url = new URL(TI_STREAM_PATH, window.location.origin);
  return new EventSource(url.toString(), { withCredentials: true });
}

export function createAnomalyEventStream(): EventSource {
  if (USE_MOCK_SSE) {
    return new MockAnomalyEventSource() as unknown as EventSource;
  }
  const url = new URL(ANOMALY_STREAM_PATH, window.location.origin);
  return new EventSource(url.toString(), { withCredentials: true });
}

export function createQueueEventStream(): EventSource {
  if (USE_MOCK_SSE) {
    return new MockTaskEventSource() as unknown as EventSource;
  }
  const url = new URL(QUEUE_STREAM_PATH, window.location.origin);
  return new EventSource(url.toString(), { withCredentials: true });
}

export function createDetectionEventStream(): EventSource {
  if (USE_MOCK_SSE) {
    return new MockDetectionEventSource() as unknown as EventSource;
  }
  const url = new URL(DETECTION_STREAM_PATH, window.location.origin);
  return new EventSource(url.toString(), { withCredentials: true });
}
