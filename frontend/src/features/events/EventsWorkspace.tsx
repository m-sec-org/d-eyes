import './EventsWorkspace.css';
import { useCallback, useEffect, useMemo, useState } from 'react';
import dayjs from 'dayjs';
import relativeTime from 'dayjs/plugin/relativeTime';
import {
  App,
  Badge,
  Button,
  Card,
  Col,
  Collapse,
  Divider,
  Empty,
  Form,
  Input,
  InputNumber,
  List,
  Row,
  Select,
  Skeleton,
  Space,
  Statistic,
  Switch,
  Tabs,
  Tag,
  Tooltip,
  Typography,
} from 'antd';
import { ReloadOutlined } from '@ant-design/icons';
import { PageHeader } from '@/components/layout/PageHeader';
import { useSystemEvents } from '@/hooks/useSystemEvents';
import { useDetectionStream } from '@/hooks/useDetectionStream';
import { useDetectionEventStore } from '@/store/detectionEvents';
import type { SystemEventQueryParams } from '@/services/api/events';
import type { SystemEventRecord, DetectionStreamEvent } from '@/services/types';
import { useCollectorConfigs } from '@/hooks/useCollectorConfigs';
import { createTask } from '@/services/api/taskActions';

dayjs.extend(relativeTime);

const { Title, Paragraph } = Typography;

const priorityOptions = [
  { label: 'High', value: 'high' },
  { label: 'Normal', value: 'normal' },
  { label: 'Low', value: 'low' },
];

const collectorKindOptions = [
  { label: '所有类型', value: '' },
  { label: 'ebpf', value: 'ebpf' },
  { label: 'etw', value: 'etw' },
  { label: 'detection-engine', value: 'detection-engine' },
];

const HEATMAP_BUCKETS = 12;

function formatEventLabel(event: SystemEventRecord) {
  const source = event.source || event.collector || '未知来源';
  return `${event.event_type} · ${source}`;
}

function formatPayloadPreview(payload?: unknown) {
  if (!payload) return '无 payload';
  const data = typeof payload === 'string' ? payload : JSON.stringify(payload);
  return data.slice(0, 160) + (data.length > 160 ? '…' : '');
}

export function EventsWorkspace() {
  const [priorities, setPriorities] = useState<string[]>(['high']);
  const [collectorKind, setCollectorKind] = useState('');
  const [eventType, setEventType] = useState('');
  const [keyword, setKeyword] = useState('');
  const [agentId, setAgentId] = useState('');
  const [selectedCollectorId, setSelectedCollectorId] = useState<string>();
  const [collectorSaving, setCollectorSaving] = useState(false);
  const [quickActionLoading, setQuickActionLoading] = useState<string | null>(null);
  const [respondingDetectionId, setRespondingDetectionId] = useState<string | null>(null);
  const [advancedOpen, setAdvancedOpen] = useState(false);
  const [sideTab, setSideTab] = useState('stats');
  const [form] = Form.useForm();
  const { message } = App.useApp();

  useDetectionStream();

  const filters = useMemo<SystemEventQueryParams>(() => {
    const payload: SystemEventQueryParams = {
      priorities,
      collector_kind: collectorKind || undefined,
      event_type: eventType.trim() || undefined,
    };
    const trimmedKeyword = keyword.trim();
    if (trimmedKeyword) {
      payload.source = trimmedKeyword;
    }
    const trimmedAgent = agentId.trim();
    if (trimmedAgent) {
      payload.agent_id = trimmedAgent;
    }
    return payload;
  }, [agentId, collectorKind, eventType, keyword, priorities]);

  const {
    events,
    stats,
    statsHistory,
    hasMore,
    loadMore,
    isLoading,
    isLoadingMore,
    refresh,
    refreshStats,
    statsLoading,
  } = useSystemEvents(filters, { pageSize: 120, includeStats: true, statsIntervalMs: 45000 });

  const detectionEventStoreEvents = useDetectionEventStore((state) => state.events);
  const detectionEvents = useMemo(
    () => detectionEventStoreEvents.slice(0, 20),
    [detectionEventStoreEvents]
  );
  const detectionStatus = useDetectionEventStore((state) => state.status);
  const { collectors, isLoading: collectorsLoading, save: saveCollectorConfig } = useCollectorConfigs();
  const selectedCollector = useMemo(
    () => collectors.find((item) => item.id === selectedCollectorId) ?? collectors[0],
    [collectors, selectedCollectorId]
  );

  useEffect(() => {
    if (!selectedCollectorId && collectors.length > 0) {
      setSelectedCollectorId(collectors[0].id);
    }
  }, [collectors, selectedCollectorId]);

  useEffect(() => {
    if (selectedCollector) {
      form.setFieldsValue({
        priority: selectedCollector.priority ?? 'normal',
        storage_tier: selectedCollector.storage_tier,
        sampling_rate: selectedCollector.sampling_rate,
        lag_threshold: selectedCollector.lag_threshold,
        enabled: selectedCollector.enabled,
      });
    }
  }, [form, selectedCollector]);

  const topEventTypes = useMemo(() => {
    if (!stats?.by_event_type) return [] as Array<[string, number]>;
    return Object.entries(stats.by_event_type)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5);
  }, [stats?.by_event_type]);

  const topSources = useMemo(() => {
    if (!stats?.by_source) return [] as Array<[string, number]>;
    return Object.entries(stats.by_source)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5);
  }, [stats?.by_source]);

  const heatmapSamples = useMemo(() => {
    const samples = statsHistory.slice(0, HEATMAP_BUCKETS).reverse();
    const values = samples.map((sample) => sample.stats.total ?? 0);
    const max = Math.max(...values, 1);
    return samples.map((sample) => ({
      timestamp: sample.timestamp,
      value: sample.stats.total ?? 0,
      intensity: sample.stats.total ? sample.stats.total / max : 0,
    }));
  }, [statsHistory]);

  const handleCollectorSubmit = useCallback(
    async (values: { priority: string; storage_tier: string; sampling_rate: number; lag_threshold: number; enabled: boolean }) => {
      if (!selectedCollector) return;
      setCollectorSaving(true);
      try {
        await saveCollectorConfig(selectedCollector.id, values);
        message.success('Collector 配置已更新');
      } catch (error) {
        console.error(error);
        message.error('更新 Collector 失败');
      } finally {
        setCollectorSaving(false);
      }
    },
    [message, saveCollectorConfig, selectedCollector]
  );

  const respondShortcuts = useMemo(
    () => [
      {
        id: 'block-process',
        label: '阻断恶意进程',
        description: '对热点主机执行阻断动作',
        payload: { playbook: 'block_process', scope: 'agent', priority: 5 },
      },
      {
        id: 'memory-scan',
        label: '内存扫描',
        description: '触发内存扫描 Respond 任务',
        payload: { playbook: 'memory_scan', scope: 'fleet', priority: 4 },
      },
      {
        id: 'isolation',
        label: '网络隔离',
        description: '隔离异常节点，防止扩散',
        payload: { playbook: 'isolate_host', scope: 'agent', priority: 5 },
      },
    ],
    []
  );

  const handleRespondShortcut = useCallback(
    async (shortcutId: string, metadata: Record<string, unknown>) => {
      setQuickActionLoading(shortcutId);
      const normalizedMetadata = Object.fromEntries(
        Object.entries(metadata).map(([key, value]) => [key, String(value)])
      ) as Record<string, string>;
      try {
        await createTask({
          type: 'respond',
          priority: Number(metadata.priority) || 5,
          metadata: {
            ...normalizedMetadata,
            triggered_from: 'events-workspace',
          },
        });
        message.success('已触发 Respond 任务');
      } catch (error) {
        console.error(error);
        message.error('创建 Respond 任务失败');
      } finally {
        setQuickActionLoading(null);
      }
    },
    [message]
  );

  const handleDetectionRespond = useCallback(
    async (event: DetectionStreamEvent) => {
      setRespondingDetectionId(event.task_id);
      try {
        await createTask({
          type: 'respond',
          priority: 5,
          metadata: {
            detection_id: event.metadata?.detection_id ?? event.task_id,
            agent_id: event.metadata?.agent_id ?? event.agent_id ?? '',
            rule: event.metadata?.rule ?? event.task_type,
            triggered_from: 'detection-feed',
          },
        });
        message.success('已为检测结果创建 Respond 任务');
      } catch (error) {
        console.error(error);
        message.error('Respond 创建失败');
      } finally {
        setRespondingDetectionId(null);
      }
    },
    [message]
  );

  return (
    <div className="events-workspace">
      <PageHeader
        title="事件工作台"
        description="汇总 ETW/eBPF 事件、实时检测告警与多 collector 运行态"
        breadcrumbs={[
          { label: '洞察', path: '/risks' },
          { label: '事件工作台' },
        ]}
        extra={
          <Space>
            <Button icon={<ReloadOutlined />} onClick={() => refresh()} disabled={isLoading}>
              刷新列表
            </Button>
            <Button icon={<ReloadOutlined />} onClick={() => refreshStats()} loading={statsLoading}>
              刷新统计
            </Button>
          </Space>
        }
      />

      <Card className="events-filters" title="过滤条件" aria-label="事件过滤条件">
        <Form layout="vertical" className="events-filters-form">
          <Row gutter={16} className="events-filters-basic">
            <Col xs={24} md={8}>
              <Form.Item label="优先级">
                <Select
                  mode="multiple"
                  allowClear
                  options={priorityOptions}
                  value={priorities}
                  onChange={setPriorities}
                  placeholder="优先级"
                />
              </Form.Item>
            </Col>
            <Col xs={24} md={6}>
              <Form.Item label="Collector 类型">
                <Select options={collectorKindOptions} value={collectorKind} onChange={setCollectorKind} />
              </Form.Item>
            </Col>
            <Col xs={24} md={5}>
              <Form.Item label="事件类型">
                <Input
                  placeholder="event_type"
                  value={eventType}
                  onChange={(event) => setEventType(event.target.value)}
                  allowClear
                />
              </Form.Item>
            </Col>
            <Col xs={24} md={5}>
              <Form.Item label="来源 / Source">
                <Input
                  placeholder="source / collector"
                  value={keyword}
                  onChange={(event) => setKeyword(event.target.value)}
                  allowClear
                />
              </Form.Item>
            </Col>
          </Row>

          <Collapse
            ghost
            className="events-filters-advanced"
            activeKey={advancedOpen || agentId ? ['advanced'] : []}
            onChange={(keys) => setAdvancedOpen((keys as string[]).includes('advanced'))}
            items={[
              {
                key: 'advanced',
                label: (
                  <Space size="small">
                    <span>高级过滤</span>
                    {agentId && <Tag color="blue">Agent ID</Tag>}
                  </Space>
                ),
                children: (
                  <Row gutter={16}>
                    <Col xs={24} md={8}>
                      <Form.Item label="Agent ID">
                        <Input
                          placeholder="agent-id 或名称"
                          value={agentId}
                          onChange={(event) => setAgentId(event.target.value)}
                          allowClear
                        />
                      </Form.Item>
                    </Col>
                  </Row>
                ),
              },
            ]}
          />
        </Form>
      </Card>

      <Row gutter={24} className="events-main">
        <Col xl={16} lg={24}>
          <Card
            title="事件时间线"
            aria-label="事件时间线"
            extra={
              <Space size="small">
                <Tag color={isLoading ? 'blue' : 'green'}>{isLoading ? '加载中' : '最新'}</Tag>
                {hasMore && (
                  <Button size="small" onClick={loadMore} loading={isLoadingMore}>
                    加载更多
                  </Button>
                )}
              </Space>
            }
          >
            {events.length === 0 ? (
              <Empty description={isLoading ? '加载中…' : '暂无事件'} />
            ) : (
              <div className="timeline-scroll">
                {events.map((event) => (
                  <div
                    key={event.id ?? `${event.agent_id ?? 'agent'}-${event.timestamp ?? 'unknown'}`}
                    className="timeline-row"
                  >
                    <div className="timeline-time">
                      <span className="timeline-time-primary">{dayjs(event.timestamp).format('HH:mm:ss')}</span>
                      <span className="timeline-time-secondary">{dayjs(event.received_at).fromNow()}</span>
                    </div>
                    <div className="timeline-body">
                      <div className="timeline-priority-indicator" data-priority={event.priority ?? 'normal'} />
                      <div className="timeline-content">
                        <div className="timeline-item-header">
                          <Title level={5}>{formatEventLabel(event)}</Title>
                          <Tag>{event.priority?.toUpperCase()}</Tag>
                        </div>
                        <Paragraph type="secondary" className="timeline-meta">
                          Agent: {event.agent_name || event.agent_id} · Tier: {event.storage_tier || 'hot'}
                        </Paragraph>
                        <Paragraph className="timeline-payload">
                          <Tooltip title={formatPayloadPreview(event.payload ?? event.metadata)}>
                            {formatPayloadPreview(event.payload ?? event.metadata)}
                          </Tooltip>
                        </Paragraph>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </Card>
          <Card title="事件热图" className="events-heatmap" aria-label="事件热图">
            {heatmapSamples.length === 0 ? (
              <Empty description="暂无历史样本" />
            ) : (
              <div className="heatmap-grid">
                {heatmapSamples.map((sample) => (
                  <Tooltip
                    key={sample.timestamp}
                    title={`${dayjs(sample.timestamp).format('HH:mm:ss')} · ${sample.value} events`}
                  >
                    <div
                      className="heatmap-cell"
                      style={{ opacity: Math.max(0.15, sample.intensity) }}
                    />
                  </Tooltip>
                ))}
              </div>
            )}
          </Card>
        </Col>
        <Col xl={8} lg={24}>
          <Card title="Respond 快捷操作" aria-label="respond 快捷操作">
            <Space direction="vertical" style={{ width: '100%' }}>
              {respondShortcuts.map((shortcut) => (
                <div key={shortcut.id} className="respond-shortcut">
                  <Space direction="vertical" size={0}>
                    <Title level={5}>{shortcut.label}</Title>
                    <Paragraph type="secondary">{shortcut.description}</Paragraph>
                  </Space>
                  <Button
                    type="primary"
                    ghost
                    loading={quickActionLoading === shortcut.id}
                    onClick={() => handleRespondShortcut(shortcut.id, shortcut.payload)}
                  >
                    触发 Respond
                  </Button>
                </div>
              ))}
            </Space>
          </Card>


          <Card
            className="events-side-panel"
            title="运行洞察"
            aria-label="事件统计与响应"
            extra={
              <Space size="small">
                <Badge status={badgeStatus(detectionStatus)} text={`SSE: ${detectionStatus}`} />
                <Tag>{detectionEvents.length} 告警</Tag>
              </Space>
            }
          >
            <Tabs
              activeKey={sideTab}
              onChange={setSideTab}
              className="events-side-panel__tabs"
              items={[
                {
                  key: 'stats',
                  label: '统计',
                  children: (
                    <div className="events-side-panel__scroll">
                      <Row gutter={16} style={{ marginBottom: 12 }}>
                        <Col span={12}>
                          <Statistic title="累计事件" value={stats?.total ?? 0} />
                        </Col>
                        <Col span={12}>
                          <Statistic title="过滤后数量" value={events.length} />
                        </Col>
                      </Row>
                      <Divider orientation="left">Top Event Types</Divider>
                      {topEventTypes.length === 0 && <Paragraph type="secondary">暂无数据</Paragraph>}
                      {topEventTypes.map(([type, count]) => (
                        <div key={type} className="stats-row">
                          <span>{type}</span>
                          <Tag>{count}</Tag>
                        </div>
                      ))}
                      <Divider orientation="left">Top Sources</Divider>
                      {topSources.length === 0 && <Paragraph type="secondary">暂无数据</Paragraph>}
                      {topSources.map(([source, count]) => (
                        <div key={source || 'unknown'} className="stats-row">
                          <span>{source || '未知来源'}</span>
                          <Tag>{count}</Tag>
                        </div>
                      ))}
                      <Divider orientation="left">统计历史</Divider>
                      <List
                        size="small"
                        dataSource={statsHistory.slice(0, 5)}
                        renderItem={(item) => (
                          <List.Item>
                            <span>{dayjs(item.timestamp).fromNow()}</span>
                            <Tag>{item.stats.total}</Tag>
                          </List.Item>
                        )}
                      />
                    </div>
                  ),
                },
                {
                  key: 'detections',
                  label: `检测 (${detectionEvents.length})`,
                  children: (
                    <div className="events-side-panel__scroll detection-feed">
                      {detectionEvents.length === 0 ? (
                        <Empty description="暂无告警" />
                      ) : (
                        <List
                          size="small"
                          dataSource={detectionEvents}
                          renderItem={(item) => (
                            <List.Item>
                              <div className="detection-feed-item">
                                <div className="detection-feed-header">
                                  <Tag color={severityColor(item.severity)}>{item.severity?.toUpperCase() ?? 'INFO'}</Tag>
                                  <span className="rule-name">{item.metadata?.rule ?? item.task_type}</span>
                                </div>
                                <Paragraph type="secondary" className="detection-message">
                                  {item.message ?? '无描述'}
                                </Paragraph>
                                <div className="detection-meta">
                                  <span>Agent {item.metadata?.agent_id ?? item.agent_id?.slice(0, 8)}</span>
                                  <span>{dayjs(item.updated_at).fromNow()}</span>
                                </div>
                                <Button
                                  type="link"
                                  size="small"
                                  onClick={() => handleDetectionRespond(item)}
                                  loading={respondingDetectionId === item.task_id}
                                >
                                  触发 Respond
                                </Button>
                              </div>
                            </List.Item>
                          )}
                        />
                      )}
                    </div>
                  ),
                },
                {
                  key: 'respond',
                  label: 'Respond / 快捷',
                  children: (
                    <div className="events-side-panel__scroll respond-panel">
                      <Space direction="vertical" style={{ width: '100%' }}>
                        {respondShortcuts.map((shortcut) => (
                          <div key={shortcut.id} className="respond-shortcut">
                            <Space direction="vertical" size={0}>
                              <Title level={5}>{shortcut.label}</Title>
                              <Paragraph type="secondary">{shortcut.description}</Paragraph>
                            </Space>
                            <Button
                              type="primary"
                              ghost
                              loading={quickActionLoading === shortcut.id}
                              onClick={() => handleRespondShortcut(shortcut.id, shortcut.payload)}
                            >
                              触发 Respond
                            </Button>
                          </div>
                        ))}
                      </Space>
                    </div>
                  ),
                },
              ]}
            />
          </Card>

          <Card
            title="Collector 控制面"
            aria-label="collector 控制面"
            extra={
              <Select
                aria-label="Collector选择器"
                value={selectedCollector?.id}
                onChange={setSelectedCollectorId}
                size="small"
                style={{ minWidth: 160 }}
                options={collectors.map((collector) => ({
                  label: collector.name,
                  value: collector.id,
                }))}
                loading={collectorsLoading}
              />
            }
          >
            {collectorsLoading && <Skeleton active paragraph={{ rows: 3 }} />}
            {!collectorsLoading && selectedCollector && (
              <Space direction="vertical" size="middle" style={{ width: '100%' }}>
                <Space size="small" wrap>
                  <Tag color={collectorStatusColor(selectedCollector.status)}>{selectedCollector.status ?? 'unknown'}</Tag>
                  <Tag>{selectedCollector.kind}</Tag>
                  <Tag>{selectedCollector.region ?? 'N/A'}</Tag>
                  <Tag color={selectedCollector.enabled ? 'green' : 'red'}>
                    {selectedCollector.enabled ? '已启用' : '已禁用'}
                  </Tag>
                </Space>
                <Paragraph type="secondary" className="collector-description">
                  {selectedCollector.description ?? '暂无描述'}
                </Paragraph>
                <Paragraph type="secondary" style={{ marginBottom: 0 }}>
                  最近心跳：{selectedCollector.last_heartbeat ? dayjs(selectedCollector.last_heartbeat).fromNow() : '未知'}
                </Paragraph>
                <Form
                  layout="vertical"
                  form={form}
                  onFinish={handleCollectorSubmit}
                  initialValues={{
                    priority: 'normal',
                    storage_tier: 'hot',
                    sampling_rate: 0.5,
                    lag_threshold: 5,
                    enabled: true,
                  }}
                >
                  <Form.Item label="优先级" name="priority">
                    <Select
                      options={[
                        { label: 'High', value: 'high' },
                        { label: 'Normal', value: 'normal' },
                        { label: 'Low', value: 'low' },
                      ]}
                    />
                  </Form.Item>
                  <Form.Item label="存储层级" name="storage_tier">
                    <Select
                      options={[
                        { label: 'Hot', value: 'hot' },
                        { label: 'Warm', value: 'warm' },
                        { label: 'Cold', value: 'cold' },
                      ]}
                    />
                  </Form.Item>
                  <Form.Item label="采样率" name="sampling_rate" rules={[{ type: 'number', min: 0, max: 1 }]}>
                    <InputNumber step={0.05} min={0} max={1} style={{ width: '100%' }} />
                  </Form.Item>
                  <Form.Item label="Lag 阈值 (秒)" name="lag_threshold" rules={[{ type: 'number', min: 0 }]}>
                    <InputNumber min={0} style={{ width: '100%' }} />
                  </Form.Item>
                  <Form.Item label="是否启用" name="enabled" valuePropName="checked">
                    <Switch />
                  </Form.Item>
                  <Form.Item>
                    <Button type="primary" htmlType="submit" loading={collectorSaving}>
                      保存配置
                    </Button>
                  </Form.Item>
                </Form>
              </Space>
            )}
          </Card>
        </Col>
      </Row>
    </div>
  );
}

function severityColor(severity?: string) {
  if (!severity) return 'blue';
  const normalized = severity.toLowerCase();
  if (normalized === 'critical') return 'magenta';
  if (normalized === 'high') return 'volcano';
  if (normalized === 'medium') return 'gold';
  if (normalized === 'low') return 'geekblue';
  return 'blue';
}

function badgeStatus(status: string) {
  switch (status) {
    case 'connected':
      return 'success';
    case 'connecting':
      return 'processing';
    default:
      return 'error';
  }
}

function collectorStatusColor(status?: string | null) {
  if (!status) return 'default';
  if (status === 'healthy') return 'green';
  if (status === 'lagging') return 'orange';
  if (status === 'disabled') return 'red';
  return 'blue';
}
