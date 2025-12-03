import { useEffect } from 'react';
import useSWR from 'swr';
import { fetchQueueSummary } from '@/services/api/queues';
import { createQueueEventStream } from '@/services/api/sse';
import { useQueueSummaryStore } from '@/store/queueSummary';

export function useQueueSummary() {
  const summary = useQueueSummaryStore((state) => state.summary);
  const history = useQueueSummaryStore((state) => state.history);
  const setSummary = useQueueSummaryStore((state) => state.setSummary);
  const status = useQueueSummaryStore((state) => state.status);
  const setStatus = useQueueSummaryStore((state) => state.setStatus);

  const { data, error, mutate, isLoading } = useSWR('queue-summary', fetchQueueSummary, {
    revalidateOnFocus: false,
  });

  useEffect(() => {
    if (data) {
      setSummary(data);
    }
  }, [data, setSummary]);

  useEffect(() => {
    const source = createQueueEventStream();
    let stopped = false;

    const handleMessage = (event: MessageEvent) => {
      try {
        const parsed = JSON.parse(event.data) as Partial<ReturnType<typeof fetchQueueSummary>>;
        if (parsed && typeof parsed === 'object' && (parsed as any).queue_depth !== undefined) {
          setSummary(
            {
              queue_depth: Number(parsed.queue_depth ?? 0),
              bas_queue_depth: Number(parsed.bas_queue_depth ?? 0),
              in_flight: Number(parsed.in_flight ?? 0),
              bas_in_flight: Number(parsed.bas_in_flight ?? 0),
              status_counts: parsed.status_counts ?? {},
              updated_at: parsed.updated_at ?? new Date().toISOString(),
            },
            true
          );
        }
      } catch {
        // ignore
      }
    };

    source.onopen = () => setStatus('connected');
    source.onerror = () => {
      setStatus('disconnected');
      if (!stopped) {
        setTimeout(() => {
          setStatus('connecting');
        }, 2000);
      }
    };
    source.onmessage = handleMessage;

    return () => {
      stopped = true;
      source.close();
    };
  }, [setSummary, setStatus]);

  return {
    summary: summary ?? data,
    history,
    status,
    isLoading: isLoading && !summary,
    error,
    refresh: mutate,
  };
}
