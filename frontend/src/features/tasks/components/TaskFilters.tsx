import { Card, Segmented, Input, Space, Button, Select } from 'antd';
import type { TaskFiltersState, SavedView, TaskStatusFilter } from '../hooks/useTaskFilters';

interface TaskFiltersProps {
  filters: TaskFiltersState;
  views: SavedView[];
  onStatusChange: (status: TaskStatusFilter) => void;
  onSearchChange: (search: string) => void;
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

export function TaskFilters({
  filters,
  views,
  onStatusChange,
  onSearchChange,
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
            showSearch
            placeholder="视图列表"
            style={{ minWidth: 200 }}
            value={filters.savedView}
            options={views.map((view) => ({ label: view.name, value: view.id }))}
            optionFilterProp="label"
            aria-label="保存视图列表"
            onChange={(value) => {
              if (value) onApplyView(value);
            }}
          />
          <Button
            onClick={() => {
              const name = prompt('保存为视图：请输入名称');
              if (name) onSaveView(name);
            }}
            aria-label="保存当前筛选条件为视图"
          >
            保存视图
          </Button>
          {filters.savedView && (
            <Button danger onClick={() => onRemoveView(filters.savedView!)} aria-label="删除当前视图">
              删除视图
            </Button>
          )}
        </Space>
      </Space>
    </Card>
  );
}
