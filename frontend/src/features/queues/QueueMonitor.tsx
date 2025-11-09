import { useMemo, useState } from 'react';
import dayjs from 'dayjs';
import { Alert, Button, Card, Empty, Space, Table, Tag, Timeline, Typography } from 'antd';
import type { ColumnsType } from 'antd/es/table';
import { ReloadOutlined, FileSearchOutlined } from '@ant-design/icons';
import { PageHeader } from '@/components/layout/PageHeader';

type QueueItem = {
  id: string;
  taskType: string;
  status: 'pending' | 'running' | 'blocked';
  priority: number;
  agent?: string;
  updatedAt: string;
};

const MOCK_QUEUE: QueueItem[] = [
  {
    id: 'f81d4fae-7dec-11d0-a765-00a0c91e6bf6',
    taskType: 'respond',
    status: 'running',
    priority: 1,
    agent: 'edge-apj-01',
    updatedAt: dayjs().subtract(2, 'minute').toISOString(),
  },
  {
    id: 'f81d4fae-7dec-11d0-a765-00a0c91e6bf7',
    taskType: 'inventory',
    status: 'pending',
    priority: 2,
    agent: undefined,
    updatedAt: dayjs().subtract(6, 'minute').toISOString(),
  },
  {
    id: 'f81d4fae-7dec-11d0-a765-00a0c91e6bf8',
    taskType: 'baseline',
    status: 'blocked',
    priority: 3,
    agent: 'edge-emea-02',
    updatedAt: dayjs().subtract(12, 'minute').toISOString(),
  },
];

const STATUS_COLORS: Record<QueueItem['status'], string> = {
  pending: 'default',
  running: 'processing',
  blocked: 'error',
};

export function QueueMonitor() {
  const [loading, setLoading] = useState(false);
  const [data, setData] = useState(MOCK_QUEUE);

  const columns: ColumnsType<QueueItem> = useMemo(
    () => [
      {
        title: '任务 ID',
        dataIndex: 'id',
        key: 'id',
        render: (value: string) => <Typography.Text code>{value.slice(0, 8)}</Typography.Text>,
      },
      {
        title: '任务类型',
        dataIndex: 'taskType',
        key: 'taskType',
        render: (value: string) => value.toUpperCase(),
      },
      {
        title: '状态',
        dataIndex: 'status',
        key: 'status',
        render: (value: QueueItem['status']) => <Tag color={STATUS_COLORS[value]}>{value}</Tag>,
      },
      {
        title: '优先级',
        dataIndex: 'priority',
        key: 'priority',
        render: (value: number) => `P${value}`,
      },
      {
        title: '处理 Agent',
        dataIndex: 'agent',
        key: 'agent',
        render: (value?: string) => value ?? '待分配',
      },
      {
        title: '最近更新',
        dataIndex: 'updatedAt',
        key: 'updatedAt',
        render: (value: string) => dayjs(value).format('MM-DD HH:mm:ss'),
      },
    ],
    []
  );

  const handleRefresh = () => {
    setLoading(true);
    setTimeout(() => {
      setData((prev) => [...prev]);
      setLoading(false);
    }, 600);
  };

  return (
    <div className="queue-monitor">
      <Space direction="vertical" size="large" style={{ width: '100%' }}>
        <PageHeader
          title="命令队列"
          description="查看响应/巡检任务在各 Agent 队列中的调度情况"
          breadcrumbs={[
            { label: '运营', path: '/' },
            { label: '命令队列' },
          ]}
          extra={
            <Space>
              <Button icon={<ReloadOutlined />} onClick={handleRefresh} loading={loading}>
                刷新
              </Button>
              <Button icon={<FileSearchOutlined />} type="link">
                查看排障指引
              </Button>
            </Space>
          }
        />

        <Alert
          type="info"
          showIcon
          message="提示"
          description="命令队列当前展示为本地模拟数据，后续将与 Server /queues API 接入实时状态。"
        />

        <Card title="队列详情">
          <Table
            rowKey="id"
            columns={columns}
            dataSource={data}
            loading={loading}
            pagination={false}
            locale={{ emptyText: <Empty description="暂无队列数据" /> }}
            aria-label="命令队列表格"
            aria-busy={loading}
          />
        </Card>

        <Card title="调度事件">
          <Timeline
            aria-label="调度事件时间线"
            items={data.map((item) => ({
              color: STATUS_COLORS[item.status],
              children: (
                <Space direction="vertical" size={0}>
                  <Typography.Text strong>
                    {item.taskType} · {item.status}
                  </Typography.Text>
                  <Typography.Text type="secondary">
                    Agent: {item.agent ?? '待分配'} · {dayjs(item.updatedAt).format('MM-DD HH:mm:ss')}
                  </Typography.Text>
                </Space>
              ),
            }))}
          />
        </Card>
      </Space>
    </div>
  );
}
