import { create } from 'zustand';
import type { ThreatIntelEvent } from '@/services/types';

export type ThreatIntelStreamStatus = 'connecting' | 'connected' | 'disconnected';

interface ThreatIntelEventState {
  status: ThreatIntelStreamStatus;
  events: ThreatIntelEvent[];
  windowSize: number;
  addEvent: (event: ThreatIntelEvent) => void;
  setStatus: (status: ThreatIntelStreamStatus) => void;
  setWindowSize: (size: number) => void;
  reset: () => void;
}

const MIN_WINDOW = 100;
const MAX_WINDOW = 600;
const DEFAULT_WINDOW = 200;

const clamp = (size: number) => Math.min(Math.max(size, MIN_WINDOW), MAX_WINDOW);

const next = (events: ThreatIntelEvent[], limit: number) => {
  if (events.length <= limit) {
    return events;
  }
  return events.slice(0, limit);
};

export const useThreatIntelEventStore = create<ThreatIntelEventState>((set) => ({
  status: 'connecting',
  events: [],
  windowSize: DEFAULT_WINDOW,
  addEvent: (event) =>
    set((state) => ({
      events: next([event, ...state.events], state.windowSize),
    })),
  setStatus: (status) => set({ status }),
  setWindowSize: (size) =>
    set((state) => {
      const windowSize = clamp(size);
      return {
        windowSize,
        events: next(state.events, windowSize),
      };
    }),
  reset: () => set({ status: 'connecting', events: [], windowSize: DEFAULT_WINDOW }),
}));
