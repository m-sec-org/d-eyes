import useSWR from 'swr';
import { getSummary } from '@/services/api/reports';

export function useRiskSummary(type: string = 'respond') {
  const { data, isLoading, error, mutate } = useSWR(['risk-summary', type], () => getSummary(type));
  const summary = data ?? { items: [], totals: {}, status: {} };
  return {
    summary,
    isLoading,
    error,
    refresh: mutate,
  };
}
