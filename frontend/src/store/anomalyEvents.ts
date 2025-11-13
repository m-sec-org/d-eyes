import { create } from 'zustand';
import type { AnomalyEvent } from '@/services/types';

export type AnomalyStreamStatus = 'connecting' | 'connected' | 'disconnected';

interface AnomalyEventState {
  status: AnomalyStreamStatus;
  events: AnomalyEvent[];
  windowSize: number;
  addEvent: (event: AnomalyEvent) => void;
  setStatus: (status: AnomalyStreamStatus) => void;
  setWindowSize: (size: number) => void;
  reset: () => void;
}

const MIN_WINDOW = 60;
const MAX_WINDOW = 400;
const DEFAULT_WINDOW = 160;

const clamp = (size: number) => Math.min(Math.max(size, MIN_WINDOW), MAX_WINDOW);

const trim = (events: AnomalyEvent[], limit: number) => {
  if (events.length <= limit) {
    return events;
  }
  return events.slice(0, limit);
};

export const useAnomalyEventStore = create<AnomalyEventState>((set) => ({
  status: 'connecting',
  events: [],
  windowSize: DEFAULT_WINDOW,
  addEvent: (event) =>
    set((state) => ({
      events: trim([event, ...state.events], state.windowSize),
    })),
  setStatus: (status) => set({ status }),
  setWindowSize: (size) =>
    set((state) => {
      const windowSize = clamp(size);
      return {
        windowSize,
        events: trim(state.events, windowSize),
      };
    }),
  reset: () => set({ status: 'connecting', events: [], windowSize: DEFAULT_WINDOW }),
}));
