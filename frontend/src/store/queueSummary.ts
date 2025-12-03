import { create } from 'zustand';
import type { QueueSummary } from '@/services/api/queues';

export type QueueStreamStatus = 'connecting' | 'connected' | 'disconnected';

interface QueueSnapshot extends QueueSummary {
  timestamp: string;
}

interface QueueSummaryState {
  summary?: QueueSummary;
  status: QueueStreamStatus;
  history: QueueSnapshot[];
  setSummary: (summary: QueueSummary, fromStream?: boolean) => void;
  setStatus: (status: QueueStreamStatus) => void;
  reset: () => void;
}

export const useQueueSummaryStore = create<QueueSummaryState>((set) => ({
  summary: undefined,
  status: 'connecting',
  history: [],
  setSummary: (summary, fromStream) =>
    set((state) => {
      const snapshot: QueueSnapshot = { ...summary, timestamp: new Date().toISOString() };
      return {
        summary,
        history: fromStream ? [snapshot, ...state.history].slice(0, 50) : state.history,
      };
    }),
  setStatus: (status) => set({ status }),
  reset: () => set({ summary: undefined, status: 'connecting', history: [] }),
}));
