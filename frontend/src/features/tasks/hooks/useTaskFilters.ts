import { useCallback, useEffect, useMemo, useState } from 'react';

export type TaskStatusFilter = 'all' | 'pending' | 'running' | 'failed' | 'succeeded';

export interface TaskFiltersState {
  status: TaskStatusFilter;
  search: string;
  savedView?: string;
}

const STORAGE_KEY = 'd-eyes:task-filters';
const VIEWS_KEY = 'd-eyes:task-views';

export interface SavedView {
  id: string;
  name: string;
  filters: TaskFiltersState;
}

const DEFAULT_FILTERS: TaskFiltersState = {
  status: 'all',
  search: '',
};

export function useTaskFilters() {
  const [filters, setFilters] = useState<TaskFiltersState>(() => {
    if (typeof window === 'undefined') return DEFAULT_FILTERS;
    const raw = window.localStorage.getItem(STORAGE_KEY);
    if (!raw) return DEFAULT_FILTERS;
    try {
      return { ...DEFAULT_FILTERS, ...(JSON.parse(raw) as TaskFiltersState) };
    } catch {
      return DEFAULT_FILTERS;
    }
  });

  const [views, setViews] = useState<SavedView[]>(() => {
    if (typeof window === 'undefined') return [];
    const raw = window.localStorage.getItem(VIEWS_KEY);
    if (!raw) return [];
    try {
      return JSON.parse(raw) as SavedView[];
    } catch {
      return [];
    }
  });

  useEffect(() => {
    if (typeof window === 'undefined') return;
    window.localStorage.setItem(STORAGE_KEY, JSON.stringify(filters));
  }, [filters]);

  useEffect(() => {
    if (typeof window === 'undefined') return;
    window.localStorage.setItem(VIEWS_KEY, JSON.stringify(views));
  }, [views]);

  const setStatus = useCallback((status: TaskStatusFilter) => {
    setFilters((prev) => ({ ...prev, status }));
  }, []);

  const setSearch = useCallback((search: string) => {
    setFilters((prev) => ({ ...prev, search }));
  }, []);

  const saveCurrentView = useCallback(
    (name: string) => {
      const id = crypto.randomUUID();
      const nextView: SavedView = { id, name, filters };
      setViews((prev) => [...prev, nextView]);
      setFilters((prev) => ({ ...prev, savedView: id }));
    },
    [filters]
  );

  const applyView = useCallback(
    (viewId: string) => {
      const view = views.find((item) => item.id === viewId);
      if (view) {
        setFilters({ ...view.filters, savedView: viewId });
      }
    },
    [views]
  );

  const removeView = useCallback(
    (viewId: string) => {
      setViews((prev) => prev.filter((item) => item.id !== viewId));
      setFilters((prev) => (prev.savedView === viewId ? { ...prev, savedView: undefined } : prev));
    },
    []
  );

  const statusQuery = useMemo(() => {
    if (filters.status === 'all') return undefined;
    return filters.status;
  }, [filters.status]);

  return {
    filters,
    views,
    statusQuery,
    setStatus,
    setSearch,
    saveCurrentView,
    applyView,
    removeView,
  };
}
