import { renderHook, act, waitFor } from '@testing-library/react';
import { SWRConfig } from 'swr';
import { describe, expect, it, beforeEach } from 'vitest';
import type { ReactNode } from 'react';
import { useSystemEvents } from '../useSystemEvents';
import { useSystemEventStore } from '@/store/systemEvents';

function createWrapper() {
  const cache = new Map();
  return ({ children }: { children: ReactNode }) => (
    <SWRConfig value={{ provider: () => cache, dedupingInterval: 0 }}>{children}</SWRConfig>
  );
}

describe('useSystemEvents hook', () => {
  beforeEach(() => {
    useSystemEventStore.getState().reset();
  });

  it('loads events/stats and appends more records via cursor pagination', async () => {
    const wrapper = createWrapper();
    const { result } = renderHook(
      () => useSystemEvents({ priorities: ['high'] }, { pageSize: 2, includeStats: true }),
      { wrapper }
    );

    await waitFor(() => expect(result.current.events.length).toBeGreaterThan(0));
    expect(result.current.stats?.total).toBeGreaterThan(0);
    expect(result.current.hasMore).toBe(true);
    expect(useSystemEventStore.getState().filters.priorities).toEqual(['high']);

    const initialLength = result.current.events.length;
    await act(async () => {
      await result.current.loadMore();
    });

    expect(result.current.events.length).toBeGreaterThan(initialLength);
    expect(result.current.hasMore).toBe(false);
    expect(result.current.nextCursor).toBeUndefined();

    const firstHistorySample = result.current.statsHistory.length;
    await act(async () => {
      await result.current.refreshStats();
    });
    expect(result.current.statsHistory.length).toBeGreaterThan(firstHistorySample);
  });
});
