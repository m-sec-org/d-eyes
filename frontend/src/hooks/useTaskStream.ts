import { useEffect } from 'react';
import { TaskEventSchema } from '@/services/api/schemas';
import { createTaskEventStream } from '@/services/api/sse';
import { useTaskEventStore } from '@/store/taskEvents';

export function useTaskStream(channel?: string) {
  const addEvent = useTaskEventStore((state) => state.addEvent);
  const setStatus = useTaskEventStore((state) => state.setStatus);

  useEffect(() => {
    let source: EventSource | null = null;
    let retryDelay = 2000;
    let stopped = false;

    const connect = () => {
      setStatus('connecting');
      source = createTaskEventStream(channel);
      source.onopen = () => {
        retryDelay = 2000;
        setStatus('connected');
      };
      source.onmessage = (event) => {
        const parsed = TaskEventSchema.safeParse(JSON.parse(event.data));
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
  }, [channel, addEvent, setStatus]);
}
