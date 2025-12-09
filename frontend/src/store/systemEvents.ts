import { create } from 'zustand';
import type { SystemEventAggregates, SystemEventCursor, SystemEventRecord } from '@/services/types';
import type { SystemEventQueryParams } from '@/services/api/events';

interface SystemEventStatsSample {
  timestamp: string;
  stats: SystemEventAggregates;
}

interface SetEventsPayload {
  events: SystemEventRecord[];
  cursor?: SystemEventCursor;
  hasMore: boolean;
  filters?: SystemEventQueryParams;
}

interface SystemEventsState {
  filters: SystemEventQueryParams;
  events: SystemEventRecord[];
  nextCursor?: SystemEventCursor;
  hasMore: boolean;
  isLoadingMore: boolean;
  stats?: SystemEventAggregates;
  statsHistory: SystemEventStatsSample[];
  setEvents: (payload: SetEventsPayload) => void;
  appendEvents: (payload: Omit<SetEventsPayload, 'filters'>) => void;
  setStats: (stats: SystemEventAggregates) => void;
  setFilters: (filters: SystemEventQueryParams) => void;
  setLoadingMore: (loading: boolean) => void;
  reset: () => void;
}

const STATS_HISTORY_LIMIT = 48;

const dedupe = (records: SystemEventRecord[]) => {
  const seen = new Set<string>();
  return records.filter((record) => {
    if (seen.has(record.id)) {
      return false;
    }
    seen.add(record.id);
    return true;
  });
};

const mergeEvents = (current: SystemEventRecord[], next: SystemEventRecord[]) => {
  if (next.length === 0) {
    return current;
  }
  const seen = new Set(current.map((record) => record.id));
  const merged = [...current];
  next.forEach((record) => {
    if (!seen.has(record.id)) {
      merged.push(record);
    }
  });
  return merged;
};

export const useSystemEventStore = create<SystemEventsState>((set) => ({
  filters: {},
  events: [],
  nextCursor: undefined,
  hasMore: false,
  isLoadingMore: false,
  stats: undefined,
  statsHistory: [],
  setEvents: ({ events, cursor, hasMore, filters }) =>
    set(() => ({
      events: dedupe(events),
      nextCursor: cursor,
      hasMore,
      filters: filters ?? {},
    })),
  appendEvents: ({ events, cursor, hasMore }) =>
    set((state) => ({
      events: mergeEvents(state.events, events),
      nextCursor: cursor,
      hasMore,
    })),
  setStats: (stats) =>
    set((state) => {
      const sample: SystemEventStatsSample = { timestamp: new Date().toISOString(), stats };
      return {
        stats,
        statsHistory: [sample, ...state.statsHistory].slice(0, STATS_HISTORY_LIMIT),
      };
    }),
  setFilters: (filters) => set({ filters }),
  setLoadingMore: (isLoadingMore) => set({ isLoadingMore }),
  reset: () =>
    set({
      filters: {},
      events: [],
      nextCursor: undefined,
      hasMore: false,
      isLoadingMore: false,
      stats: undefined,
      statsHistory: [],
    }),
}));
