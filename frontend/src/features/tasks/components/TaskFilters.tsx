import { Card, Segmented, Input, Space, Button, Select, Spin } from 'antd';
import type { TaskFiltersState, TaskStatusFilter } from '../hooks/useTaskFilters';
import type { TaskView } from '@/services/types';

interface TaskFiltersProps {
  filters: TaskFiltersState;
  views: TaskView[];
  viewsLoading?: boolean;
  savingView?: boolean;
  onStatusChange: (status: TaskStatusFilter) => void;
  onSearchChange: (search: string) => void;
  onPageSizeChange: (size: number) => void;
  onSaveView: (name: string) => void;
  onApplyView: (viewId: string) => void;
  onRemoveView: (viewId: string) => void;
}

const STATUSES: { label: string; value: TaskStatusFilter }[] = [
  { label: '全部', value: 'all' },
  { label: '待执行', value: 'pending' },
  { label: '进行中', value: 'running' },
  { label: '已完成', value: 'succeeded' },
  { label: '失败', value: 'failed' },
];

const PAGE_SIZE_OPTIONS = [
  { label: '每页 25 条', value: 25 },
  { label: '每页 50 条', value: 50 },
  { label: '每页 100 条', value: 100 },
];

export function TaskFilters({
  filters,
  views,
  viewsLoading = false,
  savingView = false,
  onStatusChange,
  onSearchChange,
  onPageSizeChange,
  onSaveView,
  onApplyView,
  onRemoveView,
}: TaskFiltersProps) {
  return (
    <Card styles={{ body: { padding: '16px 20px' } }} style={{ marginBottom: 16 }}>
      <Space direction="vertical" style={{ width: '100%' }} size="large">
        <Segmented
          value={filters.status}
          onChange={(value) => onStatusChange(value as TaskStatusFilter)}
          options={STATUSES.map((status) => ({ label: status.label, value: status.value }))}
          block
          aria-label="任务状态筛选"
        />
        <Space wrap style={{ width: '100%' }}>
          <Input
            allowClear
            placeholder="搜索任务 ID / 目标 / 场景..."
            style={{ minWidth: 220 }}
            value={filters.search}
            onChange={(event) => onSearchChange(event.target.value)}
            aria-label="任务搜索"
          />
          <Select
            value={filters.pageSize}
            style={{ width: 140 }}
            options={PAGE_SIZE_OPTIONS}
            onChange={(value) => onPageSizeChange(value)}
            aria-label="每页条数"
          />
          <Select
            showSearch
            placeholder="视图列表"
            style={{ minWidth: 200 }}
            value={filters.viewId}
            options={views.map((view) => ({ label: view.name, value: view.id }))}
            optionFilterProp="label"
            aria-label="保存视图列表"
            loading={viewsLoading}
            allowClear
            onChange={(value) => {
              if (!value) {
                onApplyView('');
                return;
              }
              onApplyView(value);
            }}
            notFoundContent={viewsLoading ? <Spin size="small" /> : '暂无视图'}
          />
          <Button
            onClick={() => {
              const name = prompt('保存为视图：请输入名称');
              if (name) onSaveView(name);
            }}
            aria-label="保存当前筛选条件为视图"
            loading={savingView}
          >
            保存视图
          </Button>
          {filters.viewId && (
            <Button danger onClick={() => onRemoveView(filters.viewId!)} aria-label="删除当前视图">
              删除视图
            </Button>
          )}
        </Space>
      </Space>
    </Card>
  );
}
