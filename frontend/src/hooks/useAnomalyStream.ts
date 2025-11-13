import { useEffect } from 'react';
import { AnomalyEventSchema } from '@/services/api/schemas';
import { createAnomalyEventStream } from '@/services/api/sse';
import { useAnomalyEventStore } from '@/store/anomalyEvents';

export function useAnomalyStream() {
  const addEvent = useAnomalyEventStore((state) => state.addEvent);
  const setStatus = useAnomalyEventStore((state) => state.setStatus);

  useEffect(() => {
    let source: EventSource | null = null;
    let retryDelay = 2000;
    let stopped = false;

    const connect = () => {
      setStatus('connecting');
      source = createAnomalyEventStream();
      source.onopen = () => {
        retryDelay = 2000;
        setStatus('connected');
      };
      source.onmessage = (event) => {
        const parsed = AnomalyEventSchema.safeParse(JSON.parse(event.data));
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
