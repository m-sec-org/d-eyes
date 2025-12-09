import { useCallback, useEffect, useMemo } from 'react';
import useSWR from 'swr';
import {
  fetchSystemEvents,
  fetchSystemEventStats,
  serializeEventQueryKey,
  type SystemEventQueryParams,
  type NormalizedSystemEventQuery,
} from '@/services/api/events';
import { useSystemEventStore } from '@/store/systemEvents';

const DEFAULT_STATS_INTERVAL = 30000;

interface UseSystemEventsOptions {
  pageSize?: number;
  includeStats?: boolean;
  statsIntervalMs?: number;
}

export function useSystemEvents(
  filters: SystemEventQueryParams = {},
  options: UseSystemEventsOptions = {}
) {
  const serializedFilters = useMemo(
    () => serializeEventQueryKey(filters, { limit: options.pageSize }),
    [filters, options.pageSize]
  );

  const normalizedFilters = useMemo(
    () => JSON.parse(serializedFilters) as NormalizedSystemEventQuery,
    [serializedFilters]
  );

  const events = useSystemEventStore((state) => state.events);
  const hasMore = useSystemEventStore((state) => state.hasMore);
  const nextCursor = useSystemEventStore((state) => state.nextCursor);
  const stats = useSystemEventStore((state) => state.stats);
  const statsHistory = useSystemEventStore((state) => state.statsHistory);
  const isLoadingMore = useSystemEventStore((state) => state.isLoadingMore);
  const setEvents = useSystemEventStore((state) => state.setEvents);
  const appendEvents = useSystemEventStore((state) => state.appendEvents);
  const setStats = useSystemEventStore((state) => state.setStats);
  const setFilters = useSystemEventStore((state) => state.setFilters);
  const setLoadingMore = useSystemEventStore((state) => state.setLoadingMore);

  useEffect(() => {
    setFilters(normalizedFilters);
  }, [normalizedFilters, setFilters]);

  const eventsKey = useMemo(
    () => ['system-events', serializedFilters],
    [serializedFilters]
  );

  const {
    data: eventsResponse,
    error,
    isLoading,
    mutate,
  } = useSWR(eventsKey, () => fetchSystemEvents(normalizedFilters), {
    revalidateOnFocus: false,
    keepPreviousData: true,
  });

  useEffect(() => {
    if (eventsResponse) {
      setEvents({
        events: eventsResponse.items,
        cursor: eventsResponse.next_cursor ?? undefined,
        hasMore: Boolean(eventsResponse.next_cursor),
        filters: normalizedFilters,
      });
    }
  }, [eventsResponse, normalizedFilters, setEvents]);

  const statsKey = useMemo(() => {
    if (options.includeStats === false) {
      return null;
    }
    return ['system-event-stats', serializedFilters];
  }, [options.includeStats, serializedFilters]);

  const {
    data: statsResponse,
    error: statsError,
    isLoading: statsLoading,
    mutate: refreshStats,
  } = useSWR(
    statsKey,
    () => fetchSystemEventStats(normalizedFilters),
    {
      refreshInterval: options.statsIntervalMs ?? DEFAULT_STATS_INTERVAL,
      revalidateOnFocus: false,
    }
  );

  useEffect(() => {
    if (statsResponse) {
      setStats(statsResponse);
    }
  }, [setStats, statsResponse]);

  const loadMore = useCallback(async () => {
    if (!hasMore || !nextCursor || isLoadingMore) {
      return;
    }
    setLoadingMore(true);
    try {
      const response = await fetchSystemEvents({
        ...normalizedFilters,
        cursor_id: nextCursor.id,
        cursor_time: nextCursor.received_at,
      });
      appendEvents({
        events: response.items,
        cursor: response.next_cursor ?? undefined,
        hasMore: Boolean(response.next_cursor),
      });
    } finally {
      setLoadingMore(false);
    }
  }, [appendEvents, hasMore, isLoadingMore, nextCursor, normalizedFilters, setLoadingMore]);

  return {
    events,
    stats,
    statsHistory,
    hasMore,
    nextCursor,
    isLoading,
    error,
    refresh: mutate,
    loadMore,
    isLoadingMore,
    statsLoading,
    statsError,
    refreshStats,
  };
}
