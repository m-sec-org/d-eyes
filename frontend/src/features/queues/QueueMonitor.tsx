import { useMemo, useState } from 'react';
import { Card, Space, Statistic, Tag, Timeline, Typography, Alert, Button, Table, Input } from 'antd';
import type { ColumnsType } from 'antd/es/table';
import { ReloadOutlined } from '@ant-design/icons';
import { PageHeader } from '@/components/layout/PageHeader';
import { useQueueSummary } from '@/hooks/useQueueSummary';
import { useTaskEventStore } from '@/store/taskEvents';
import type { TaskEvent } from '@/services/types';

export function QueueMonitor() {
  const { summary, history, status, isLoading, refresh } = useQueueSummary();
  const taskEvents = useTaskEventStore((state) => state.events);

  const statusCounts = summary?.status_counts ?? {};
  const blockedCount = statusCounts.blocked ?? 0;
  const failedCount = statusCounts.failed ?? 0;

  const timelineItems = history.map((snapshot) => ({
    color: snapshot.queue_depth > 5 ? 'red' : 'blue',
    children: (
      <Space direction="vertical" size={0}>
        <Typography.Text strong>
          队列深度 {snapshot.queue_depth} · 运行 {snapshot.in_flight}
        </Typography.Text>
        <Typography.Text type="secondary">{new Date(snapshot.updated_at).toLocaleTimeString()}</Typography.Text>
      </Space>
    ),
  }));

  const agentColumns: ColumnsType<AgentActivityRow> = [
    {
      title: 'Agent',
      dataIndex: 'agent',
      key: 'agent',
      render: (value: string) => <Typography.Text code>{value}</Typography.Text>,
    },
    {
      title: '运行中',
      dataIndex: 'running',
      key: 'running',
    },
    {
      title: '最近事件',
      dataIndex: 'lastEvent',
      key: 'lastEvent',
      render: (value: string) => value ?? '—',
    },
    {
      title: '任务类型',
      dataIndex: 'taskType',
      key: 'taskType',
      render: (value: string) => value ?? '—',
    },
    {
      title: '时间',
      dataIndex: 'updatedAt',
      key: 'updatedAt',
      render: (value: string) => (value ? new Date(value).toLocaleTimeString() : '—'),
    },
  ];

  const [agentFilter, setAgentFilter] = useState('');
  const [showAllAgents, setShowAllAgents] = useState(false);
  const [typeFilter, setTypeFilter] = useState('');
  const [showAllTypes, setShowAllTypes] = useState(false);

  const agentRows = useMemo(() => buildAgentRows(taskEvents), [taskEvents]);
  const filteredAgentRows = agentRows.filter((row) => row.agent.toLowerCase().includes(agentFilter.toLowerCase()));
  const visibleAgents = showAllAgents ? filteredAgentRows : filteredAgentRows.slice(0, 5);

  const typeDistribution = useMemo(() => buildTaskTypeDistribution(taskEvents), [taskEvents]);
  const filteredTypes = typeDistribution.filter((row) => row.type.toLowerCase().includes(typeFilter.toLowerCase()));
  const visibleTypes = showAllTypes ? filteredTypes : filteredTypes.slice(0, 6);

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
              <Button icon={<ReloadOutlined />} onClick={() => refresh()} loading={isLoading}>
                刷新
              </Button>
            </Space>
          }
        />

        {status !== 'connected' && (
          <Alert
            type={status === 'disconnected' ? 'error' : 'warning'}
            showIcon
            message={`队列流连接：${status}`}
            description="实时状态断开时将暂时使用最近一次快照。"
          />
        )}

        {(blockedCount > 0 || failedCount > 0) && (
          <Alert
            type="error"
            showIcon
            message="队列告警"
            description={`当前存在 ${blockedCount} 个阻塞和 ${failedCount} 个失败任务，请检查 Agent 或调度日志。`}
          />
        )}

        <Card title="队列概览">
          <Space size="large" wrap>
            <Statistic title="队列深度" value={summary?.queue_depth ?? 0} />
            <Statistic title="BAS 队列" value={summary?.bas_queue_depth ?? 0} />
            <Statistic title="运行中" value={summary?.in_flight ?? 0} />
            <Statistic title="BAS 运行" value={summary?.bas_in_flight ?? 0} />
          </Space>
          <Space style={{ marginTop: 16 }} wrap>
            {Object.entries(statusCounts).map(([statusKey, count]) => (
              <Tag key={statusKey}>
                {statusKey}: {count}
              </Tag>
            ))}
          </Space>
        </Card>

        <Card title="任务类型分布">
          <Space style={{ marginBottom: 12 }} wrap>
            <Input
              allowClear
              size="small"
              placeholder="按类型过滤"
              value={typeFilter}
              onChange={(event) => setTypeFilter(event.target.value)}
              style={{ width: 200 }}
            />
            <Button size="small" onClick={() => setShowAllTypes((prev) => !prev)}>
              {showAllTypes ? '收起' : '展开全部'}
            </Button>
          </Space>
          <Space wrap>
            {visibleTypes.length === 0 && <Typography.Text type="secondary">暂无任务事件</Typography.Text>}
            {visibleTypes.map((item) => (
              <Tag key={item.type}>
                {item.type}：{item.count}
              </Tag>
            ))}
          </Space>
        </Card>

        <Card title="Agent 活动（最近事件）">
          <Space style={{ marginBottom: 12 }} wrap>
            <Input
              allowClear
              size="small"
              placeholder="搜索 Agent"
              value={agentFilter}
              onChange={(event) => setAgentFilter(event.target.value)}
              style={{ width: 200 }}
            />
            <Button size="small" onClick={() => setShowAllAgents((prev) => !prev)}>
              {showAllAgents ? '收起' : '展开全部'}
            </Button>
          </Space>
          <Table
            rowKey="agent"
            columns={agentColumns}
            dataSource={visibleAgents}
            size="small"
            pagination={false}
            locale={{ emptyText: '暂无 Agent 活动' }}
          />
        </Card>

        <Card title="调度事件（最近）">
          <Timeline items={timelineItems} />
        </Card>
      </Space>
    </div>
  );
}

interface AgentActivityRow {
  agent: string;
  running: number;
  lastEvent?: string;
  taskType?: string;
  updatedAt?: string;
}

function buildAgentRows(events: TaskEvent[]): AgentActivityRow[] {
  const map = new Map<string, AgentActivityRow>();
  events.slice(0, 200).forEach((event) => {
    if (!event.agent_id) return;
    const agent = event.agent_id.slice(0, 8);
    const row =
      map.get(agent) ??
      {
        agent,
        running: 0,
      };
    if (event.status === 'running' || event.status === 'leased') {
      row.running += 1;
    }
    if (!row.updatedAt || new Date(event.updated_at).getTime() > new Date(row.updatedAt).getTime()) {
      row.updatedAt = event.updated_at;
      row.lastEvent = event.event;
      row.taskType = event.task_type;
    }
    map.set(agent, row);
  });
  return Array.from(map.values()).sort((a, b) =>
    b.running === a.running ? (b.updatedAt ?? '').localeCompare(a.updatedAt ?? '') : b.running - a.running
  );
}

function buildTaskTypeDistribution(events: TaskEvent[]) {
  const counts = new Map<string, number>();
  events.slice(0, 200).forEach((event) => {
    if (!event.task_type) return;
    counts.set(event.task_type, (counts.get(event.task_type) ?? 0) + 1);
  });
  return Array.from(counts.entries())
    .map(([type, count]) => ({ type, count }))
    .sort((a, b) => b.count - a.count);
}
