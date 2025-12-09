import './QueueMonitor.css';
import { useMemo, useState } from 'react';
import { Bar } from '@ant-design/plots';
import { Card, Space, Statistic, Tag, Typography, Alert, Button, Table, Input, Tabs, Empty, Badge } from 'antd';
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
  const [typeFilter, setTypeFilter] = useState('');
  const [showAllTypes, setShowAllTypes] = useState(false);
  const [panelTab, setPanelTab] = useState('types');
  const [eventFilter, setEventFilter] = useState('');

  const agentRows = useMemo(() => buildAgentRows(taskEvents), [taskEvents]);
  const filteredAgentRows = agentRows.filter((row) => row.agent.toLowerCase().includes(agentFilter.toLowerCase()));

  const typeDistribution = useMemo(() => buildTaskTypeDistribution(taskEvents), [taskEvents]);
  const filteredTypes = typeDistribution.filter((row) => row.type.toLowerCase().includes(typeFilter.toLowerCase()));
  const typesToRender = useMemo(
    () => (showAllTypes ? filteredTypes : filteredTypes.slice(0, 8)),
    [filteredTypes, showAllTypes]
  );
  const typeColorMap = useMemo(() => {
    const map = new Map<string, string>();
    typesToRender.forEach((item, index) => map.set(item.type, TYPE_BAR_COLORS[index % TYPE_BAR_COLORS.length]));
    return map;
  }, [typesToRender]);
  const typeBarHeight = Math.max(120, typesToRender.length * 36);

  const typeBarConfig = useMemo(
    () => ({
      data: typesToRender,
      xField: 'count',
      yField: 'type',
      legend: false,
      seriesField: 'type',
      color: (datum: { type: string }) => typeColorMap.get(datum.type) ?? TYPE_BAR_COLORS[0],
      barStyle: { radius: [0, 6, 6, 0] },
      label: {
        position: 'right',
        formatter: (datum: { count: number }) => `${datum.count}`,
      },
      tooltip: {
        showMarkers: false,
        formatter: (datum: { type: string; count: number }) => ({
          name: datum.type,
          value: `${datum.count} 次`,
        }),
      },
      xAxis: {
        label: {
          formatter: (value: string) => value,
        },
      },
      yAxis: {
        label: { autoRotate: false },
      },
      interactions: [{ type: 'active-region' }],
    }),
    [typeColorMap, typesToRender]
  );

  const queueEvents = useMemo(() => taskEvents.slice(0, 200), [taskEvents]);
  const filteredQueueEvents = useMemo(() => {
    if (!eventFilter.trim()) return queueEvents;
    const keyword = eventFilter.toLowerCase();
    return queueEvents.filter((event) => {
      const text = `${event.task_id ?? ''} ${event.task_type ?? ''} ${event.event ?? ''} ${event.agent_id ?? ''}`.toLowerCase();
      return text.includes(keyword);
    });
  }, [eventFilter, queueEvents]);

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

        <Card
          title="队列运行洞察"
          extra={<Badge status={statusBadge(status)} text={`SSE: ${status}`} />}
          className="queue-monitor-panel"
        >
          <Tabs
            activeKey={panelTab}
            onChange={setPanelTab}
            items={[
              {
                key: 'types',
                label: '任务类型',
                children: (
                  <div className="queue-panel-scroll">
                    <Space style={{ marginBottom: 12 }} wrap align="center">
                      <Input
                        allowClear
                        size="small"
                        placeholder="按类型过滤"
                        value={typeFilter}
                        onChange={(event) => setTypeFilter(event.target.value)}
                        style={{ width: 200 }}
                      />
                      <Button size="small" onClick={() => setShowAllTypes((prev) => !prev)}>
                        {showAllTypes ? '仅展示前 8 个' : '展开全部'}
                      </Button>
                      <Typography.Text type="secondary">
                        {filteredTypes.length
                          ? `显示 ${typesToRender.length} / ${filteredTypes.length} 种任务`
                          : '暂无任务事件'}
                      </Typography.Text>
                    </Space>
                    {typesToRender.length === 0 ? (
                      <Empty description="暂无任务事件" />
                    ) : (
                      <div style={{ minHeight: typeBarHeight }}>
                        <Bar {...typeBarConfig} height={typeBarHeight} />
                      </div>
                    )}
                  </div>
                ),
              },
              {
                key: 'agents',
                label: 'Agent 活动',
                children: (
                  <div className="queue-panel-scroll">
                    <Space style={{ marginBottom: 12 }} wrap align="center">
                      <Input
                        allowClear
                        size="small"
                        placeholder="搜索 Agent"
                        value={agentFilter}
                        onChange={(event) => setAgentFilter(event.target.value)}
                        style={{ width: 200 }}
                      />
                      <Typography.Text type="secondary">
                        共 {filteredAgentRows.length} 个 Agent
                      </Typography.Text>
                    </Space>
                    <Table
                      rowKey="agent"
                      columns={agentColumns}
                      dataSource={filteredAgentRows}
                      size="small"
                      pagination={{
                        pageSize: 5,
                        showSizeChanger: false,
                        showTotal: (total, range) => `显示 ${range[0]}-${range[1]} / ${total} 个 Agent`,
                      }}
                      locale={{ emptyText: '暂无 Agent 活动' }}
                      scroll={{ y: 320 }}
                    />
                  </div>
                ),
              },
              {
                key: 'timeline',
                label: '调度事件',
                children: (
                  <div className="queue-panel-scroll">
                    <Space style={{ marginBottom: 12 }} wrap>
                      <Input
                        allowClear
                        size="small"
                        placeholder="搜索任务/Agent"
                        value={eventFilter}
                        onChange={(event) => setEventFilter(event.target.value)}
                        style={{ width: 220 }}
                      />
                      <Button size="small" icon={<ReloadOutlined />} onClick={() => refresh()}>
                        刷新
                      </Button>
                    </Space>
                    {filteredQueueEvents.length === 0 ? (
                      <Empty description="暂无调度事件" />
                    ) : (
                      filteredQueueEvents.map((event) => (
                        <div
                          key={`${event.task_id ?? 'task'}-${event.updated_at ?? event.event ?? 'unknown'}`}
                          className="queue-timeline-row"
                        >
                          <div className="queue-timeline-meta">
                            <Typography.Text strong>{event.task_type ?? '任务'}</Typography.Text>
                            <Typography.Text type="secondary">
                              {event.updated_at ? new Date(event.updated_at).toLocaleTimeString() : '未知时间'}
                            </Typography.Text>
                          </div>
                          <div className="queue-timeline-body">
                            <div className="queue-timeline-status" data-status={event.status ?? 'unknown'} />
                            <div>
                              <Typography.Text>
                                Agent {event.agent_id?.slice(0, 8) ?? 'unknown'} · {event.event}
                              </Typography.Text>
                              <Typography.Paragraph type="secondary" ellipsis={{ rows: 2, tooltip: event.message }}>
                                {event.message ?? '无附加信息'}
                              </Typography.Paragraph>
                            </div>
                          </div>
                        </div>
                      ))
                    )}
                  </div>
                ),
              },
            ]}
          />
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

const TYPE_BAR_COLORS = ['#1677ff', '#13c2c2', '#52c41a', '#faad14', '#eb2f96', '#722ed1', '#a0d911', '#2f54eb'];

function statusBadge(status: string) {
  if (status === 'connected') return 'success';
  if (status === 'connecting') return 'processing';
  if (status === 'reconnecting') return 'warning';
  return 'error';
}
