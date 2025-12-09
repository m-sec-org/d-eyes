import { create } from 'zustand';
import type { DetectionStreamEvent } from '@/services/types';

export type DetectionStreamStatus = 'connecting' | 'connected' | 'disconnected';

interface DetectionEventState {
  status: DetectionStreamStatus;
  events: DetectionStreamEvent[];
  windowSize: number;
  addEvent: (event: DetectionStreamEvent) => void;
  setStatus: (status: DetectionStreamStatus) => void;
  setWindowSize: (size: number) => void;
  reset: () => void;
}

const MIN_WINDOW = 80;
const MAX_WINDOW = 800;
const DEFAULT_WINDOW = 320;

const clampWindow = (size: number) => Math.min(Math.max(size, MIN_WINDOW), MAX_WINDOW);

const trimEvents = (events: DetectionStreamEvent[], limit: number) =>
  events.length <= limit ? events : events.slice(0, limit);

export const useDetectionEventStore = create<DetectionEventState>((set) => ({
  status: 'connecting',
  events: [],
  windowSize: DEFAULT_WINDOW,
  addEvent: (event) =>
    set((state) => ({
      events: trimEvents([event, ...state.events], state.windowSize),
    })),
  setStatus: (status) => set({ status }),
  setWindowSize: (size) =>
    set((state) => {
      const windowSize = clampWindow(size);
      return {
        windowSize,
        events: trimEvents(state.events, windowSize),
      };
    }),
  reset: () => set({ status: 'connecting', events: [], windowSize: DEFAULT_WINDOW }),
}));
