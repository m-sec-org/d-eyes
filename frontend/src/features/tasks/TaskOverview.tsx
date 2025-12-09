import { useState } from 'react';
import { useTaskFilters } from './hooks/useTaskFilters';
import { useTasksData } from './hooks/useTasksData';
import type { Task } from '@/services/types';
import { TaskBoard } from './components/TaskBoard';
import { TaskFilters } from './components/TaskFilters';
import { TaskList } from './components/TaskList';
import { TaskDetailDrawer } from './components/TaskDetailDrawer';
import { TaskLiveMonitor } from './components/TaskLiveMonitor';
import { CreateTaskDrawer } from './forms/CreateTaskDrawer';
import { useTaskActions } from './hooks/useTaskActions';
import { Button, Space } from 'antd';
import { PlusOutlined, ThunderboltOutlined } from '@ant-design/icons';
import { PageHeader } from '@/components/layout/PageHeader';
import { useQueueSummary } from '@/hooks/useQueueSummary';

export function TaskOverview() {
  const filterState = useTaskFilters();
  const { tasks, summary, isLoading, isLoadingMore, canLoadMore, loadMore, refresh } = useTasksData(filterState.filters);
  const queue = useQueueSummary();
  const [selectedTask, setSelectedTask] = useState<Task | null>(null);
  const [createDrawerOpen, setCreateDrawerOpen] = useState(false);
  const { retryTask, cancelTask } = useTaskActions(refresh);

  const handleBulkRetry = async (selected: Task[]) => {
    for (const task of selected) {
      await retryTask(task);
    }
    refresh();
  };

  const handleBulkCancel = async (selected: Task[]) => {
    for (const task of selected) {
      await cancelTask(task);
    }
    refresh();
  };

  const activeViewName = filterState.views.find((view) => view.id === filterState.filters.viewId)?.name;

  return (
    <div className="task-overview">
      <Space direction="vertical" size="large" style={{ width: '100%' }}>
        <PageHeader
          title="任务指挥中心"
          description="查看队列、筛选任务、保存视图并执行快捷操作"
          breadcrumbs={[
            { label: '运营', path: '/' },
            { label: '任务' },
          ]}
          extra={
            <Space wrap>
              <Button icon={<PlusOutlined />} type="primary" onClick={() => setCreateDrawerOpen(true)}>
                新建任务
              </Button>
              <Button icon={<ThunderboltOutlined />}>从模板创建</Button>
            </Space>
          }
        />

        <TaskBoard tasks={tasks} loading={isLoading} summary={summary} />

        <TaskFilters
          filters={filterState.filters}
          views={filterState.views}
          viewsLoading={filterState.viewsLoading}
          savingView={filterState.savingView}
          onStatusChange={filterState.setStatus}
          onSearchChange={filterState.setSearch}
          onPageSizeChange={filterState.setPageSize}
          onSaveView={filterState.saveCurrentView}
          onApplyView={filterState.applyView}
          onRemoveView={filterState.removeView}
        />

        <TaskList
          tasks={tasks}
          loading={isLoading}
          loadingMore={isLoadingMore}
          canLoadMore={canLoadMore}
          onRefresh={refresh}
          onSelect={setSelectedTask}
          onRetry={retryTask}
          onCancel={cancelTask}
          onBulkRetry={handleBulkRetry}
          onBulkCancel={handleBulkCancel}
          onLoadMore={loadMore}
          activeViewName={activeViewName}
        />
        
        <TaskLiveMonitor
          tasks={tasks}
          queueSummary={queue.summary}
          queueStatus={queue.status}
        />
      </Space>

      <TaskDetailDrawer task={selectedTask} onClose={() => setSelectedTask(null)} />
      <CreateTaskDrawer open={createDrawerOpen} onClose={() => setCreateDrawerOpen(false)} onCreated={refresh} />
    </div>
  );
}
