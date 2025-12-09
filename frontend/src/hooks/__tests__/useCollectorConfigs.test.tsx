import { renderHook, waitFor, act } from '@testing-library/react';
import { describe, expect, it, beforeEach, vi } from 'vitest';
import type { ReactNode } from 'react';
import { SWRConfig } from 'swr';
import { useCollectorConfigs } from '../useCollectorConfigs';
import * as collectorApi from '@/services/api/collectors';

vi.mock('@/services/api/collectors', () => ({
  fetchCollectors: vi.fn(),
  updateCollectorConfig: vi.fn(),
}));

const mockCollectors = [
  {
    id: 'collector-hk-edge',
    name: 'HK Edge Collector',
    kind: 'ebpf',
    region: 'HK',
    priority: 'high',
    storage_tier: 'hot',
    sampling_rate: 0.5,
    lag_threshold: 3,
    enabled: true,
    status: 'healthy',
    last_heartbeat: new Date().toISOString(),
  },
];

function createWrapper() {
  const cache = new Map();
  return ({ children }: { children: ReactNode }) => (
    <SWRConfig value={{ provider: () => cache, dedupingInterval: 0 }}>{children}</SWRConfig>
  );
}

describe('useCollectorConfigs hook', () => {
  const fetchCollectorsSpy = vi.mocked(collectorApi.fetchCollectors);
  const updateCollectorSpy = vi.mocked(collectorApi.updateCollectorConfig);

  beforeEach(() => {
    fetchCollectorsSpy.mockResolvedValue(mockCollectors);
    updateCollectorSpy.mockResolvedValue(mockCollectors[0]);
  });

  it('loads collectors and saves configuration updates', async () => {
    const wrapper = createWrapper();
    const { result } = renderHook(() => useCollectorConfigs(), { wrapper });

    await waitFor(() => expect(result.current.collectors.length).toBe(1));
    expect(fetchCollectorsSpy).toHaveBeenCalledTimes(1);

    await act(async () => {
      await result.current.save('collector-hk-edge', { priority: 'normal' });
    });
    expect(updateCollectorSpy).toHaveBeenCalledWith('collector-hk-edge', { priority: 'normal' });
    expect(fetchCollectorsSpy).toHaveBeenCalledTimes(2);
  });
});
