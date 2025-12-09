import { useEffect } from 'react';
import { DetectionStreamEventSchema } from '@/services/api/schemas';
import { createDetectionEventStream } from '@/services/api/sse';
import { useDetectionEventStore } from '@/store/detectionEvents';

export function useDetectionStream() {
  const addEvent = useDetectionEventStore((state) => state.addEvent);
  const setStatus = useDetectionEventStore((state) => state.setStatus);

  useEffect(() => {
    let source: EventSource | null = null;
    let retryDelay = 2000;
    let stopped = false;

    const connect = () => {
      setStatus('connecting');
      source = createDetectionEventStream();
      source.onopen = () => {
        retryDelay = 2000;
        setStatus('connected');
      };
      source.onmessage = (event) => {
        const parsed = DetectionStreamEventSchema.safeParse(JSON.parse(event.data));
        if (parsed.success) {
          addEvent(parsed.data);
        }
      };
      source.onerror = () => {
        setStatus('disconnected');
        source?.close();
        if (!stopped) {
          setTimeout(connect, retryDelay);
          retryDelay = Math.min(retryDelay * 1.5, 15000);
        }
      };
    };

    connect();

    return () => {
      stopped = true;
      source?.close();
    };
  }, [addEvent, setStatus]);
}
