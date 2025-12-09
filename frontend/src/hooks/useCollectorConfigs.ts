import useSWR from 'swr';
import { fetchCollectors, updateCollectorConfig } from '@/services/api/collectors';
import type { CollectorConfig } from '@/services/types';

export function useCollectorConfigs() {
  const { data, error, isLoading, mutate } = useSWR<CollectorConfig[]>('collector-configs', fetchCollectors, {
    refreshInterval: 60000,
    revalidateOnFocus: false,
  });

  const save = async (
    collectorId: string,
    payload: Parameters<typeof updateCollectorConfig>[1]
  ) => {
    await updateCollectorConfig(collectorId, payload);
    await mutate();
  };

  return {
    collectors: data ?? [],
    isLoading,
    error,
    refresh: () => mutate(),
    save,
  };
}
