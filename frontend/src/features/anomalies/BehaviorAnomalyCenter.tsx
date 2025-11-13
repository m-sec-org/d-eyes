import './BehaviorAnomalyCenter.css';
import { useEffect, useMemo, useState } from 'react';
import useSWR from 'swr';
import dayjs from 'dayjs';
import relativeTime from 'dayjs/plugin/relativeTime';
import { Button, Card, Empty, Input, Select, Space, Statistic, Table, Tag, Timeline, Tooltip, Typography } from 'antd';
import type { ColumnsType } from 'antd/es/table';
import { PageHeader } from '@/components/layout/PageHeader';
import { useAnomalyStream } from '@/hooks/useAnomalyStream';
import { useAnomalyEventStore } from '@/store/anomalyEvents';
import { listAnomalies, getAnomaly, getAnomalyGraph, type AnomalyFilters } from '@/services/api/behavior';
import type { Anomaly, AnomalyGraph } from '@/services/types';

const { Title, Paragraph } = Typography;

dayjs.extend(relativeTime);

const severityColors: Record<string, string> = {
  critical: 'magenta',
  high: 'volcano',
  medium: 'gold',
  low: 'geekblue',
};

const severityThreshold: Record<string, number> = {
  critical: 90,
  high: 70,
  medium: 40,
};

const statusColors: Record<string, string> = {
  open: 'processing',
  closed: 'default',
};

const severityOptions = [
  { label: '全部级别', value: 'all' },
  { label: 'Critical (≥90)', value: 'critical' },
  { label: 'High (≥70)', value: 'high' },
  { label: 'Medium (≥40)', value: 'medium' },
];

const statusOptions = [
  { label: '全部状态', value: 'all' },
  { label: 'Open', value: 'open' },
  { label: 'Closed', value: 'closed' },
];

const limitOptions = [
  { label: '最近 25 条', value: 25 },
  { label: '最近 50 条', value: 50 },
  { label: '最近 100 条', value: 100 },
];

function severityTag(value?: string) {
  if (!value) {
    return <Tag>未知</Tag>;
  }
  const color = severityColors[value.toLowerCase()] ?? 'default';
  return <Tag color={color}>{value.toUpperCase()}</Tag>;
}

function statusTag(value?: string) {
  if (!value) {
    return <Tag>未知</Tag>;
  }
  const color = statusColors[value.toLowerCase()] ?? 'default';
  return <Tag color={color}>{value.toUpperCase()}</Tag>;
}

function formatValue(value: unknown): string {
  if (value === null || value === undefined) return '—';
  if (Array.isArray(value)) {
    return value.join(', ');
  }
  if (typeof value === 'object') {
    try {
      return JSON.stringify(value);
    } catch (error) {
      return String(value);
    }
  }
  return String(value);
}

export function BehaviorAnomalyCenter() {
  useAnomalyStream();
  const [statusFilter, setStatusFilter] = useState('open');
  const [severityFilter, setSeverityFilter] = useState('critical');
  const [searchTerm, setSearchTerm] = useState('');
  const [agentFilter, setAgentFilter] = useState('');
  const [limit, setLimit] = useState(50);
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const filters = useMemo(() => {
    const payload: AnomalyFilters = { limit };
    if (statusFilter !== 'all') {
      payload.status = statusFilter;
    }
    if (severityFilter !== 'all') {
      payload.min_score = severityThreshold[severityFilter] ?? undefined;
    }
    const trimmedIoc = searchTerm.trim();
    if (trimmedIoc) {
      payload.ioc = trimmedIoc;
    }
    const trimmedAgent = agentFilter.trim();
    if (trimmedAgent) {
      payload.agent_id = trimmedAgent;
    }
    return payload;
  }, [statusFilter, severityFilter, searchTerm, agentFilter, limit]);

  const listKey = useMemo(() => ['anomalies', JSON.stringify(filters)], [filters]);
  const {
    data: anomalyList,
    isLoading: listLoading,
    mutate: refreshList,
  } = useSWR<Anomaly[]>(listKey, () => listAnomalies(filters));
  const anomalies = anomalyList ?? [];

  useEffect(() => {
    if (!selectedId && anomalies.length > 0) {
      setSelectedId(anomalies[0].id);
    }
  }, [anomalies, selectedId]);

  useEffect(() => {
    if (selectedId && anomalies.length > 0) {
      const exists = anomalies.some((item) => item.id === selectedId);
      if (!exists) {
        setSelectedId(anomalies[0]?.id ?? null);
      }
    }
  }, [anomalies, selectedId]);

  const { data: selectedAnomaly } = useSWR(selectedId ? ['anomaly-detail', selectedId] : null, () => getAnomaly(selectedId ?? ''));
  const { data: anomalyGraph } = useSWR<AnomalyGraph | undefined>(selectedId ? ['anomaly-graph', selectedId] : null, () => getAnomalyGraph(selectedId ?? ''));
  const activeAnomaly = selectedAnomaly ?? anomalies.find((item) => item.id === selectedId);

  const columns: ColumnsType<Anomaly> = useMemo(
    () => [
      {
        title: '严重级别',
        dataIndex: 'severity',
        key: 'severity',
        render: (value: string) => severityTag(value),
      },
      {
        title: 'Agent',
        dataIndex: 'agent_id',
        key: 'agent',
        render: (value: string | null | undefined) => (value ? <code>{value.slice(0, 8)}…</code> : '未知'),
      },
      {
        title: 'IOC / 实体',
        dataIndex: 'ioc',
        key: 'ioc',
        ellipsis: true,
        render: (_: string, record: Anomaly) => record.ioc ?? record.entities?.[0] ?? '—',
      },
      {
        title: 'Score',
        dataIndex: 'score',
        key: 'score',
        render: (value: number) => value.toFixed(1),
      },
      {
        title: '状态',
        dataIndex: 'status',
        key: 'status',
        render: (value: string) => statusTag(value),
      },
      {
        title: '最近更新',
        dataIndex: 'updated_at',
        key: 'updated',
        render: (value: string) => dayjs(value).fromNow(),
      },
    ],
    []
  );

  const anomalyEvents = useAnomalyEventStore((state) => state.events);
  const streamStatus = useAnomalyEventStore((state) => state.status);
  const streamFeed = anomalyEvents.slice(0, 20);

  return (
    <div className="anomaly-center">
      <PageHeader
        title="行为异常中心"
        description="实时洞察 Agent 行为、追踪异常事件并查看关联拓扑"
        breadcrumbs={[
          { label: '洞察', path: '/risks' },
          { label: '行为异常' },
        ]}
        extra={
          <Space>
            <Tag color={streamStatus === 'connected' ? 'green' : streamStatus === 'connecting' ? 'blue' : 'red'}>
              SSE: {streamStatus}
            </Tag>
            <Button onClick={() => refreshList()} size="small">
              刷新列表
            </Button>
          </Space>
        }
      />

      <Card className="anomaly-card" title="筛选器">
        <div className="anomaly-filter-grid">
          <Input
            allowClear
            placeholder="按 IOC / IP / 关键字过滤"
            value={searchTerm}
            onChange={(event) => setSearchTerm(event.target.value)}
          />
          <Input
            allowClear
            placeholder="Agent ID"
            value={agentFilter}
            onChange={(event) => setAgentFilter(event.target.value)}
          />
          <Select value={severityFilter} options={severityOptions} onChange={(value) => setSeverityFilter(value)} />
          <Select value={statusFilter} options={statusOptions} onChange={(value) => setStatusFilter(value)} />
          <Select value={limit} options={limitOptions} onChange={(value) => setLimit(value)} />
        </div>
      </Card>

      <div className="anomaly-grid">
        <Card className="anomaly-card" title={`异常列表 (${anomalies.length})`} styles={{ body: { padding: 0 } }}>
          <Table
            className="anomaly-list-table"
            rowKey="id"
            size="small"
            loading={listLoading}
            columns={columns}
            dataSource={anomalies}
            pagination={false}
            rowClassName={(record) => (record.id === selectedId ? 'selected-row' : '')}
            onRow={(record) => ({
              onClick: () => setSelectedId(record.id),
            })}
          />
          {anomalies.length === 0 && !listLoading && <Empty description="暂无异常" style={{ margin: '2rem 0' }} />}
        </Card>

        <Card className="anomaly-card" title="异常详情">
          {activeAnomaly ? (
            <div className="anomaly-detail">
              <Space size="large" wrap>
                <Statistic title="Score" value={activeAnomaly.score} precision={1} suffix="/100" />
                <div>
                  <div>严重级别</div>
                  {severityTag(activeAnomaly.severity)}
                </div>
                <div>
                  <div>状态</div>
                  {statusTag(activeAnomaly.status)}
                </div>
              </Space>
              <div className="anomaly-meta">
                <div>
                  <span className="muted">Agent</span>
                  <code>{activeAnomaly.agent_id ?? '未知'}</code>
                </div>
                <div>
                  <span className="muted">关联任务</span>
                  <code>{activeAnomaly.task_id ?? '—'}</code>
                </div>
                <div>
                  <span className="muted">IOC / 指标</span>
                  <code>{activeAnomaly.ioc ?? '—'}</code>
                </div>
                <div>
                  <span className="muted">最近更新</span>
                  {dayjs(activeAnomaly.updated_at).format('YYYY-MM-DD HH:mm:ss')}
                </div>
              </div>
              {activeAnomaly.entities && activeAnomaly.entities.length > 0 && (
                <div>
                  <span className="muted">涉及实体</span>
                  <Space wrap>
                    {activeAnomaly.entities.map((entity) => (
                      <Tag key={entity}>{entity}</Tag>
                    ))}
                  </Space>
                </div>
              )}
              <div>
                <Title level={5}>摘要指标</Title>
                {activeAnomaly.summary && Object.keys(activeAnomaly.summary).length > 0 ? (
                  <div className="anomaly-summary-grid">
                    {Object.entries(activeAnomaly.summary).map(([key, value]) => (
                      <div key={key} className="anomaly-summary-item">
                        <span className="muted">{key}</span>
                        <span>{formatValue(value)}</span>
                      </div>
                    ))}
                  </div>
                ) : (
                  <Empty description="暂无摘要" />
                )}
              </div>
              <div>
                <Title level={5}>关联图谱</Title>
                {anomalyGraph && (anomalyGraph.nodes.length > 0 || anomalyGraph.edges.length > 0) ? (
                  <div className="anomaly-graph">
                    <div>
                      <strong>节点</strong>
                      <ul>
                        {anomalyGraph.nodes.map((node) => (
                          <li key={node.id}>
                            <Tooltip title={JSON.stringify(node.properties ?? {}, null, 2)}>
                              <span className="graph-node-type">[{node.type}]</span> {node.label ?? node.id}
                            </Tooltip>
                          </li>
                        ))}
                      </ul>
                    </div>
                    <div>
                      <strong>边</strong>
                      {anomalyGraph.edges.length > 0 ? (
                        <ul>
                          {anomalyGraph.edges.map((edge) => (
                            <li key={edge.id}>
                              {edge.source_node} → {edge.target_node} ({edge.type})
                            </li>
                          ))}
                        </ul>
                      ) : (
                        <span className="muted">暂无边</span>
                      )}
                    </div>
                  </div>
                ) : (
                  <Empty description="暂无图谱数据" />
                )}
              </div>
            </div>
          ) : (
            <Empty description="请选择一个异常" />
          )}
        </Card>
      </div>

      <Card className="anomaly-card" title="实时事件">
        {streamFeed.length > 0 ? (
          <Timeline
            mode="left"
            items={streamFeed.map((event) => ({
              color: severityColors[event.anomaly?.severity?.toLowerCase() ?? 'low'] ?? 'blue',
              label: dayjs(event.timestamp).format('HH:mm:ss'),
              children: (
                <div className="anomaly-event-item">
                  <div className="anomaly-event-header">
                    {severityTag(event.anomaly?.severity)} {statusTag(event.anomaly?.status)}
                  </div>
                  <Paragraph type="secondary" className="anomaly-event-text">
                    {event.anomaly?.summary?.reason ?? event.event}
                  </Paragraph>
                  <div className="anomaly-event-meta">
                    <span>Agent: {event.anomaly?.agent_id?.slice(0, 8) ?? '未知'}</span>
                    <span>Score: {event.anomaly?.score?.toFixed?.(1) ?? '—'}</span>
                  </div>
                </div>
              ),
            }))}
          />
        ) : (
          <Empty description="尚未收到 SSE 事件" />
        )}
      </Card>
    </div>
  );
}
