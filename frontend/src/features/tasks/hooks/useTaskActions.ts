import { useCallback, useState } from 'react';
import type { Task } from '@/services/types';
import { cancelTask, retryTask } from '@/services/api/taskActions';

export function useTaskActions(onUpdated: () => void) {
  const [loadingTaskId, setLoadingTaskId] = useState<string | null>(null);

  const retry = useCallback(
    async (task: Task) => {
      setLoadingTaskId(task.id);
      try {
        await retryTask(task.id);
        onUpdated();
      } finally {
        setLoadingTaskId(null);
      }
    },
    [onUpdated]
  );

  const cancel = useCallback(
    async (task: Task) => {
      setLoadingTaskId(task.id);
      try {
        await cancelTask(task.id);
        onUpdated();
      } finally {
        setLoadingTaskId(null);
      }
    },
    [onUpdated]
  );

  return {
    loadingTaskId,
    retryTask: retry,
    cancelTask: cancel,
  };
}
