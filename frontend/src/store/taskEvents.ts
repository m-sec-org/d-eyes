import { create } from 'zustand';
import type { TaskEvent } from '@/services/types';

export type TaskStreamStatus = 'connecting' | 'connected' | 'disconnected';

interface TaskEventState {
  status: TaskStreamStatus;
  events: TaskEvent[];
  addEvent: (event: TaskEvent) => void;
  setStatus: (status: TaskStreamStatus) => void;
}

export const useTaskEventStore = create<TaskEventState>((set) => ({
  status: 'connecting',
  events: [],
  addEvent: (event) =>
    set((state) => {
      const next = [event, ...state.events].slice(0, 200);
      return { events: next };
    }),
  setStatus: (status) => set({ status }),
}));
