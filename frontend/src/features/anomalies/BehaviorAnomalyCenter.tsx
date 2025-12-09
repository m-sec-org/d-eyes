import './BehaviorAnomalyCenter.css';
import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react';
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

const graphNodeColors: Record<string, string> = {
  agent: '#1677ff',
  connection_cluster: '#13c2c2',
  process_summary: '#722ed1',
  resource_usage: '#fa8c16',
  session_cluster: '#eb2f96',
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
  const splitContainerRef = useRef<HTMLDivElement | null>(null);
  const [splitRatio, setSplitRatio] = useState(0.58);
  const [isResizing, setIsResizing] = useState(false);
  const [isStacked, setIsStacked] = useState(false);
  const [panelHeight, setPanelHeight] = useState(520);

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
  const tableScrollY = Math.max(240, Math.round(panelHeight - 170));

  useLayoutEffect(() => {
    const element = splitContainerRef.current;
    if (!element || typeof ResizeObserver === 'undefined') {
      return;
    }
    const observer = new ResizeObserver((entries) => {
      const entry = entries[0];
      setPanelHeight(entry.contentRect.height);
      setIsStacked(entry.contentRect.width < 960);
    });
    observer.observe(element);
    return () => observer.disconnect();
  }, []);

  useEffect(() => {
    if (!isResizing) return;
    if (isStacked) {
      setIsResizing(false);
      return;
    }
    const handleMove = (event: MouseEvent) => {
      if (!splitContainerRef.current) return;
      event.preventDefault();
      const rect = splitContainerRef.current.getBoundingClientRect();
      const ratio = (event.clientX - rect.left) / rect.width;
      setSplitRatio((current) => {
        if (!Number.isFinite(ratio)) return current;
        return Math.min(0.75, Math.max(0.35, ratio));
      });
    };
    const handleTouch = (event: TouchEvent) => {
      if (!splitContainerRef.current) return;
      const touch = event.touches[0];
      if (!touch) return;
      const rect = splitContainerRef.current.getBoundingClientRect();
      const ratio = (touch.clientX - rect.left) / rect.width;
      setSplitRatio((current) => {
        if (!Number.isFinite(ratio)) return current;
        return Math.min(0.75, Math.max(0.35, ratio));
      });
    };
    const handleUp = () => setIsResizing(false);
    window.addEventListener('mousemove', handleMove);
    window.addEventListener('mouseup', handleUp);
    window.addEventListener('touchmove', handleTouch);
    window.addEventListener('touchend', handleUp);
    return () => {
      window.removeEventListener('mousemove', handleMove);
      window.removeEventListener('mouseup', handleUp);
      window.removeEventListener('touchmove', handleTouch);
      window.removeEventListener('touchend', handleUp);
    };
  }, [isResizing, isStacked]);

  const startResize = useCallback(
    (event: React.MouseEvent | React.TouchEvent) => {
      if (isStacked) return;
      event.preventDefault();
      setIsResizing(true);
    },
    [isStacked]
  );

  const splitClassName = useMemo(() => {
    const classes = ['anomaly-split'];
    if (isResizing) classes.push('is-resizing');
    if (isStacked) classes.push('is-stacked');
    return classes.join(' ');
  }, [isResizing, isStacked]);

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

      <div className={splitClassName} ref={splitContainerRef}>
        <div className="anomaly-panel" style={!isStacked ? { flexBasis: `${Math.round(splitRatio * 100)}%` } : undefined}>
          <Card className="anomaly-card anomaly-panel-card anomaly-panel-card--list" title={`异常列表 (${anomalies.length})`} styles={{ body: { padding: 0 } }}>
            <div className="anomaly-panel-scroll">
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
                scroll={{ y: tableScrollY }}
                sticky
              />
              {anomalies.length === 0 && !listLoading && <Empty description="暂无异常" style={{ margin: '2rem 0' }} />}
            </div>
          </Card>
        </div>

        {!isStacked && (
          <button
            type="button"
            className="anomaly-divider"
            onMouseDown={startResize}
            onTouchStart={startResize}
            aria-label="调整异常列表与详情宽度"
          />
        )}

        <div className="anomaly-panel" style={!isStacked ? { flexBasis: `${Math.round((1 - splitRatio) * 100)}%` } : undefined}>
          <Card className="anomaly-card anomaly-panel-card anomaly-panel-card--detail" title="异常详情">
            {activeAnomaly ? (
              <div className="anomaly-panel-scroll">
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
                      <div className="anomaly-graph-layout">
                        <div className="anomaly-graph-canvas-wrapper">
                          <RelationGraph graph={anomalyGraph} />
                        </div>
                        <div className="anomaly-graph-meta">
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
                                    {edge.source_node.slice(0, 8)} → {edge.target_node.slice(0, 8)} ({edge.type})
                                  </li>
                                ))}
                              </ul>
                            ) : (
                              <span className="muted">暂无边</span>
                            )}
                          </div>
                        </div>
                      </div>
                    ) : (
                      <Empty description="暂无图谱数据" />
                    )}
                  </div>
                </div>
              </div>
            ) : (
              <div className="anomaly-panel-scroll">
                <Empty description="请选择一个异常" />
              </div>
            )}
          </Card>
        </div>
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

interface PositionedGraphNode {
  node: AnomalyGraph['nodes'][number];
  x: number;
  y: number;
  isPrimary: boolean;
}

interface RelationGraphProps {
  graph: AnomalyGraph;
  height?: number;
}

function RelationGraph({ graph, height = 320 }: RelationGraphProps) {
  const layout = useMemo(() => {
    if (!graph || graph.nodes.length === 0) return null;
    const width = 600;
    const agentNode = graph.nodes.find((node) => node.type === 'agent');
    const others = agentNode ? graph.nodes.filter((node) => node.id !== agentNode.id) : graph.nodes;
    const viewHeight = height;
    const centerX = width / 2;
    const centerY = viewHeight / 2;
    const radius = Math.max(Math.min(centerX, centerY) - 48, 80);
    const positioned: PositionedGraphNode[] = [];
    if (agentNode) {
      positioned.push({ node: agentNode, x: centerX, y: centerY, isPrimary: true });
    }
    const totalOthers = Math.max(others.length, 1);
    others.forEach((node, index) => {
      const angle = (2 * Math.PI * index) / totalOthers;
      positioned.push({
        node,
        x: centerX + radius * Math.cos(angle),
        y: centerY + radius * Math.sin(angle),
        isPrimary: false,
      });
    });
    const pointMap = new Map(positioned.map((item) => [item.node.id, item]));
    const edges = graph.edges
      .map((edge) => {
        const source = pointMap.get(edge.source_node);
        const target = pointMap.get(edge.target_node);
        if (!source || !target) return null;
        return { edge, source, target };
      })
      .filter(Boolean) as Array<{
      edge: AnomalyGraph['edges'][number];
      source: PositionedGraphNode;
      target: PositionedGraphNode;
    }>;
    return { width, height: viewHeight, nodes: positioned, edges };
  }, [graph, height]);

  if (!layout) {
    return <Empty description="暂无图谱数据" />;
  }

  return (
    <svg
      className="anomaly-graph-canvas"
      viewBox={`0 0 ${layout.width} ${layout.height}`}
      width="100%"
      height={layout.height}
      role="img"
      aria-label="异常关联图谱"
      preserveAspectRatio="xMidYMid meet"
    >
      <defs>
        <marker id="anomaly-graph-arrow" markerWidth="8" markerHeight="8" refX="8" refY="4" orient="auto" markerUnits="strokeWidth">
          <path d="M0,0 L8,4 L0,8 z" fill="#bfbfbf" />
        </marker>
        <filter id="anomaly-node-shadow" x="-20%" y="-20%" width="140%" height="140%">
          <feDropShadow dx="0" dy="2" stdDeviation="4" floodColor="rgba(0,0,0,0.12)" />
        </filter>
      </defs>

      {layout.edges.map(({ edge, source, target }) => (
        <g key={edge.id} className="anomaly-graph-edge">
          <line
            x1={source.x}
            y1={source.y}
            x2={target.x}
            y2={target.y}
            stroke="#c4c4c4"
            strokeWidth={2}
            markerEnd="url(#anomaly-graph-arrow)"
          />
          <text
            x={(source.x + target.x) / 2}
            y={(source.y + target.y) / 2 - 6}
            className="anomaly-graph-edge-label"
            textAnchor="middle"
          >
            {edge.type}
          </text>
        </g>
      ))}

      {layout.nodes.map(({ node, x, y, isPrimary }) => {
        const color = graphNodeColors[node.type] ?? '#94a3b8';
        return (
          <g key={node.id} className="anomaly-graph-node" transform={`translate(${x}, ${y})`}>
            <circle
              r={isPrimary ? 30 : 22}
              fill={color}
              stroke={isPrimary ? '#10239e' : '#e6f4ff'}
              strokeWidth={isPrimary ? 2.5 : 1.5}
              filter="url(#anomaly-node-shadow)"
            />
            <text textAnchor="middle" dominantBaseline="middle" className="anomaly-graph-node-label">
              {node.label ?? node.type}
            </text>
          </g>
        );
      })}
    </svg>
  );
}
