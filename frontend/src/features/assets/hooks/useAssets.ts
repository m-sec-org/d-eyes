import useSWR from 'swr';
import { listAssets } from '@/services/api/assets';

export function useAssets() {
  const { data, isLoading, error, mutate } = useSWR('assets', listAssets);
  return {
    summary: data,
    isLoading,
    error,
    refresh: mutate,
  };
}
