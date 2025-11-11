import { create } from 'zustand';
import type { TaskEvent } from '@/services/types';

export type TaskStreamStatus = 'connecting' | 'connected' | 'disconnected';

interface TaskEventState {
  status: TaskStreamStatus;
  events: TaskEvent[];
  windowSize: number;
  addEvent: (event: TaskEvent) => void;
  addEvents: (incoming: TaskEvent[]) => void;
  setStatus: (status: TaskStreamStatus) => void;
  setWindowSize: (size: number) => void;
  reset: () => void;
}

const MIN_WINDOW = 150;
const MAX_WINDOW = 1000;
const DEFAULT_WINDOW = 600;

function clampWindow(size: number) {
  return Math.min(Math.max(size, MIN_WINDOW), MAX_WINDOW);
}

function nextEvents(events: TaskEvent[], limit: number) {
  if (events.length <= limit) {
    return events;
  }
  return events.slice(0, limit);
}

export const useTaskEventStore = create<TaskEventState>((set) => ({
  status: 'connecting',
  events: [],
  windowSize: DEFAULT_WINDOW,
  addEvent: (event) =>
    set((state) => ({
      events: nextEvents([event, ...state.events], state.windowSize),
    })),
  addEvents: (incoming) =>
    set((state) => ({
      events: nextEvents([...incoming, ...state.events], state.windowSize),
    })),
  setStatus: (status) => set({ status }),
  setWindowSize: (size) =>
    set((state) => {
      const windowSize = clampWindow(size);
      return {
        windowSize,
        events: nextEvents(state.events, windowSize),
      };
    }),
  reset: () => set({ status: 'connecting', events: [], windowSize: DEFAULT_WINDOW }),
}));
