import { useMemo } from 'react';
import useSWRInfinite from 'swr/infinite';
import { listTasks } from '@/services/api/tasks';
import type { TaskFiltersState } from './useTaskFilters';
import type { Task, TaskListSummary } from '@/services/types';

interface UseTasksDataResult {
  tasks: Task[];
  summary?: TaskListSummary;
  isLoading: boolean;
  isLoadingMore: boolean;
  canLoadMore: boolean;
  loadMore: () => Promise<void> | void;
  refresh: () => void;
  error: unknown;
}

export function useTasksData(filters: TaskFiltersState): UseTasksDataResult {
  const query = useMemo(() => {
    const statuses =
      filters.status === 'all'
        ? undefined
        : filters.status === 'running'
        ? ['running', 'leased']
        : [filters.status];
    return {
      statuses,
      search: filters.search || undefined,
      limit: filters.pageSize,
      view_id: filters.viewId,
    };
  }, [filters.pageSize, filters.search, filters.status, filters.viewId]);

  const getKey = (pageIndex: number, previousPageData: Awaited<ReturnType<typeof listTasks>> | null) => {
    if (pageIndex > 0 && !previousPageData?.next_cursor) {
      return null;
    }
    const payload = {
      query,
      cursor: pageIndex === 0 ? undefined : previousPageData?.next_cursor ?? undefined,
    };
    return JSON.stringify(payload);
  };

  const fetcher = async (key: string) => {
    const payload = JSON.parse(key) as { query: typeof query; cursor?: string };
    return listTasks({ ...payload.query, cursor: payload.cursor });
  };

  const { data, error, mutate, size, setSize, isValidating } = useSWRInfinite(getKey, fetcher, {
    revalidateFirstPage: true,
  });

  const tasks = useMemo(() => {
    if (!data) return [] as Task[];
    return data.flatMap((page) => page.data);
  }, [data]);

  const summary = data?.[0]?.summary;
  const lastPage = data?.[data.length - 1];
  const canLoadMore = Boolean(lastPage?.next_cursor);

  const loadMore = () => {
    if (!canLoadMore) return;
    return setSize(size + 1);
  };

  const refresh = () => {
    setSize(1);
    mutate();
  };

  const isLoading = !data && !error;
  const isLoadingMore = size > 0 && data && typeof data[size - 1] === 'undefined';

  return {
    tasks,
    summary,
    isLoading,
    isLoadingMore,
    canLoadMore,
    loadMore,
    refresh,
    error,
  };
}
