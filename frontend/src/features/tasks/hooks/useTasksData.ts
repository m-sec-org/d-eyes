import useSWR from 'swr';
import { listTasks } from '@/services/api/tasks';
import type { TaskFiltersState } from './useTaskFilters';

export function useTasksData(filters: TaskFiltersState) {
  const statusParam =
    filters.status === 'all' ? undefined : filters.status === 'running' ? 'running,leased' : filters.status;
  const { data, isLoading, error, mutate } = useSWR(['tasks', statusParam], () =>
    listTasks(
      statusParam
        ? {
            status: statusParam,
          }
        : undefined
    )
  );
  const filtered = data?.data.filter((task) => {
    if (!filters.search) return true;
    const keyword = filters.search.toLowerCase();
    const haystack = [task.id, task.type, task.metadata?.targets, task.metadata?.scenario_id]
      .filter(Boolean)
      .join(' ')
      .toLowerCase();
    return haystack.includes(keyword);
  });
  return {
    tasks: filtered ?? [],
    isLoading,
    error,
    refresh: mutate,
  };
}
