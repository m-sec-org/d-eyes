import { useEffect } from 'react';
import { ThreatIntelEventSchema } from '@/services/api/schemas';
import { createThreatIntelEventStream } from '@/services/api/sse';
import { useThreatIntelEventStore } from '@/store/threatIntelEvents';

export function useThreatIntelStream() {
  const addEvent = useThreatIntelEventStore((state) => state.addEvent);
  const setStatus = useThreatIntelEventStore((state) => state.setStatus);

  useEffect(() => {
    let source: EventSource | null = null;
    let retryDelay = 2000;
    let stopped = false;

    const connect = () => {
      setStatus('connecting');
      source = createThreatIntelEventStream();
      source.onopen = () => {
        retryDelay = 2000;
        setStatus('connected');
      };
      source.onmessage = (event) => {
        const parsed = ThreatIntelEventSchema.safeParse(JSON.parse(event.data));
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
