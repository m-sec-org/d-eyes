import useSWR from 'swr';
import { getAssetDetail } from '@/services/api/assetDetail';

export function useAssetDetail(id: string | null) {
  const { data, isLoading, error, mutate } = useSWR(id ? ['asset-detail', id] : null, () => getAssetDetail(id!));
  return { detail: data, isLoading, error, refresh: mutate };
}
