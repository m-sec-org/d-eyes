import { useCallback, useEffect, useState } from 'react';
import useSWR from 'swr';
import { message } from 'antd';
import { listTaskViews, createTaskView, deleteTaskView } from '@/services/api/taskViews';
import type { TaskView } from '@/services/types';

export type TaskStatusFilter = 'all' | 'pending' | 'running' | 'failed' | 'succeeded';

export interface TaskFiltersState {
  status: TaskStatusFilter;
  search: string;
  pageSize: number;
  viewId?: string;
}

const STORAGE_KEY = 'd-eyes:task-filters';

const DEFAULT_FILTERS: TaskFiltersState = {
  status: 'all',
  search: '',
  pageSize: 50,
};

export function useTaskFilters() {
  const [filters, setFilters] = useState<TaskFiltersState>(() => {
    if (typeof window === 'undefined') return DEFAULT_FILTERS;
    try {
      const raw = window.localStorage.getItem(STORAGE_KEY);
      if (!raw) return DEFAULT_FILTERS;
      const parsed = JSON.parse(raw) as TaskFiltersState;
      return { ...DEFAULT_FILTERS, ...parsed };
    } catch {
      return DEFAULT_FILTERS;
    }
  });

  useEffect(() => {
    if (typeof window === 'undefined') return;
    window.localStorage.setItem(STORAGE_KEY, JSON.stringify(filters));
  }, [filters]);

  const setStatus = useCallback((status: TaskStatusFilter) => {
    setFilters((prev) => ({ ...prev, status, viewId: undefined }));
  }, []);

  const setSearch = useCallback((search: string) => {
    setFilters((prev) => ({ ...prev, search, viewId: undefined }));
  }, []);

  const setPageSize = useCallback((pageSize: number) => {
    setFilters((prev) => ({ ...prev, pageSize }));
  }, []);

  const { data: viewData, isLoading: viewsLoading, mutate: refreshViews } = useSWR('task-views', listTaskViews, {
    revalidateOnFocus: false,
  });
  const views = viewData?.views ?? [];

  const [savingView, setSavingView] = useState(false);

  const saveCurrentView = useCallback(
    async (name: string) => {
      const trimmed = name.trim();
      if (!trimmed) return;
      setSavingView(true);
      try {
        const payload = {
          name: trimmed,
          filters: {
            status: filters.status,
            search: filters.search,
          },
          page_size: filters.pageSize,
        };
        const view = await createTaskView(payload);
        await refreshViews();
        setFilters((prev) => ({ ...prev, viewId: view.id }));
        message.success('视图已保存');
      } catch (error) {
        console.error(error);
        message.error('保存视图失败');
      } finally {
        setSavingView(false);
      }
    },
    [filters, refreshViews]
  );

  const applyView = useCallback(
    (viewId: string) => {
      if (!viewId) {
        setFilters((prev) => ({ ...prev, viewId: undefined }));
        return;
      }
      const view = views.find((item) => item.id === viewId);
      if (!view) return;
      const normalized = normalizeViewFilters(view, filters.pageSize);
      setFilters({ ...normalized, viewId: view.id });
    },
    [views, filters.pageSize]
  );

  const removeView = useCallback(
    async (viewId: string) => {
      try {
        await deleteTaskView(viewId);
        await refreshViews();
        if (filters.viewId === viewId) {
          setFilters((prev) => ({ ...prev, viewId: undefined }));
        }
        message.success('已删除视图');
      } catch (error) {
        console.error(error);
        message.error('删除视图失败');
      }
    },
    [filters.viewId, refreshViews]
  );

  return {
    filters,
    views,
    viewsLoading,
    savingView,
    setStatus,
    setSearch,
    setPageSize,
    saveCurrentView,
    applyView,
    removeView,
  };
}

function normalizeViewFilters(view: TaskView, fallback: number): TaskFiltersState {
  const raw = view.filters ?? {};
  const status = extractStatus(raw.status);
  const search = typeof raw.search === 'string' ? raw.search : '';
  const pageSize = typeof raw.page_size === 'number' && raw.page_size > 0 ? raw.page_size : fallback;
  return {
    status,
    search,
    pageSize,
  };
}

function extractStatus(value: unknown): TaskStatusFilter {
  if (typeof value === 'string' && isTaskStatusFilter(value)) {
    return value;
  }
  if (Array.isArray(value) && typeof value[0] === 'string' && isTaskStatusFilter(value[0])) {
    return value[0];
  }
  return 'all';
}

function isTaskStatusFilter(value: string): value is TaskStatusFilter {
  return ['all', 'pending', 'running', 'failed', 'succeeded'].includes(value);
}
