import type { Task } from '@/services/types';
import dayjs from 'dayjs';
import { Card, Button, Table, Tag, Space } from 'antd';
import type { ColumnsType } from 'antd/es/table';

interface TaskListProps {
  tasks: Task[];
  loading?: boolean;
  onRefresh: () => void;
  onSelect: (task: Task) => void;
  onRetry: (task: Task) => void;
  onCancel: (task: Task) => void;
}

const statusColor: Record<string, string> = {
  pending: 'default',
  running: 'processing',
  leased: 'processing',
  failed: 'error',
  succeeded: 'success',
};

export function TaskList({ tasks, loading = false, onRefresh, onSelect, onRetry, onCancel }: TaskListProps) {
  const columns: ColumnsType<Task> = [
    {
      title: 'ID',
      dataIndex: 'id',
      key: 'id',
      render: (value: string) => <span className="mono">{value.slice(0, 8)}</span>,
    },
    { title: '类型', dataIndex: 'type', key: 'type' },
    {
      title: '状态',
      dataIndex: 'status',
      key: 'status',
      render: (status: string) => <Tag color={statusColor[status] ?? 'default'}>{status}</Tag>,
    },
    { title: '优先级', dataIndex: 'priority', key: 'priority', width: 90 },
    {
      title: '目标/场景',
      dataIndex: ['metadata', 'targets'],
      key: 'target',
      render: (_: unknown, record) => record.metadata?.targets ?? record.metadata?.scenario_id ?? '—',
    },
    {
      title: '最近更新',
      dataIndex: 'updated_at',
      key: 'updated_at',
      render: (value: string) => dayjs(value).format('MM-DD HH:mm'),
    },
    {
      title: '操作',
      key: 'actions',
      render: (_: unknown, record) => (
        <Space>
          <Button size="small" onClick={() => onSelect(record)} aria-label={`查看任务 ${record.id} 详情`}>
            详情
          </Button>
          <Button size="small" onClick={() => onRetry(record)} aria-label={`重试任务 ${record.id}`}>
            重试
          </Button>
          <Button size="small" danger onClick={() => onCancel(record)} aria-label={`取消任务 ${record.id}`}>
            取消
          </Button>
        </Space>
      ),
    },
  ];

  return (
    <Card
      title="任务列表"
      extra={
        <Space aria-live="polite">
          <Button onClick={onRefresh} loading={loading} aria-label="刷新任务列表">
            刷新
          </Button>
          <Button type="link" aria-label="导出任务列表">
            导出
          </Button>
        </Space>
      }
    >
      <Table
        rowKey="id"
        columns={columns}
        dataSource={tasks}
        loading={loading}
        aria-label="任务列表表格"
        aria-busy={loading}
        pagination={{ pageSize: 10, showSizeChanger: false }}
        locale={{ emptyText: '暂无任务' }}
        scroll={{ x: true }}
      />
    </Card>
  );
}
