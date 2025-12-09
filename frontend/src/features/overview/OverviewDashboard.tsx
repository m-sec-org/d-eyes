import { useMemo, useId } from 'react';
import { Card, Col, List, Row, Skeleton, Space, Statistic, Tag, Typography, Button } from 'antd';
import { ArrowDownOutlined, ArrowUpOutlined, MinusOutlined } from '@ant-design/icons';
import dayjs from 'dayjs';
import { Link, useNavigate } from 'react-router-dom';
import { PageHeader } from '@/components/layout/PageHeader';
import { useTasksData } from '../tasks/hooks/useTasksData';
import { useAssets } from '../assets/hooks/useAssets';
import { useRiskSummary } from '../risks/hooks/useRiskSummary';
import { usePermissions, type Role } from '@/hooks/usePermissions';
import type { Task, TaskListSummary } from '@/services/types';
import type { TaskFiltersState } from '../tasks/hooks/useTaskFilters';

const { Text } = Typography;

const OVERVIEW_FILTERS: TaskFiltersState = {
  status: 'all',
  search: '',
  pageSize: 50,
};

const STAT_KEYS = ['total', 'running', 'pending', 'failed'] as const;
type StatMetricKey = (typeof STAT_KEYS)[number];
type StatTone = 'neutral' | 'info' | 'warning' | 'danger';

interface StatMetric {
  key: StatMetricKey;
  title: string;
  tone: StatTone;
  match: (task: Task) => boolean;
}

const STAT_METRICS: StatMetric[] = [
  { key: 'total', title: '任务总数', tone: 'neutral', match: () => true },
  {
    key: 'running',
    title: '运行中',
    tone: 'info',
    match: (task) => task.status === 'running' || task.status === 'leased',
  },
  { key: 'pending', title: '待执行', tone: 'warning', match: (task) => task.status === 'pending' },
  { key: 'failed', title: '失败告警', tone: 'danger', match: (task) => task.status === 'failed' },
];

const STAT_TONE_VALUE_COLOR: Record<StatTone, string> = {
  neutral: 'var(--color-text-primary)',
  info: 'var(--color-info)',
  warning: 'var(--color-warning)',
  danger: 'var(--color-danger)',
};

const STAT_TONE_CHART_COLOR: Record<StatTone, string> = {
  neutral: '#1774ff',
  info: '#13c2c2',
  warning: '#fa8c16',
  danger: '#f5222d',
};

const SPARKLINE_WIDTH = 120;
const SPARKLINE_HEIGHT = 40;

interface QuickLinkItem {
  title: string;
  description: string;
  to: string;
  roles?: Role[];
}

const QUICK_LINKS: QuickLinkItem[] = [
  { title: '任务指挥中心', description: '查看队列与筛选任务', to: '/tasks' },
  { title: '风险监控', description: 'Respond/Baseline 风险摘要', to: '/risks' },
  { title: '资产视图', description: '资产 inventory 与标签管理', to: '/assets' },
  { title: '命令队列', description: '调度/排队与 Agent 运行状态', to: '/queues', roles: ['admin'] },
];

export function OverviewDashboard() {
  const navigate = useNavigate();
  const { tasks, summary, isLoading: loadingTasks } = useTasksData(OVERVIEW_FILTERS);
  const { summary: assetSummary, isLoading: loadingAssets } = useAssets();
  const { summary: riskSummary, isLoading: loadingRisk } = useRiskSummary('respond');
  const { canAccess } = usePermissions();

  const taskStats = useMemo(() => aggregateTaskStats(summary, tasks), [summary, tasks]);
  const metricSeries = useMemo(() => buildMetricSeries(tasks), [tasks]);
  const metricTrends = useMemo(() => calculateAllTrends(metricSeries), [metricSeries]);
  const quickLinks = useMemo(
    () => QUICK_LINKS.filter((item) => canAccess(item.to, item.roles)),
    [canAccess]
  );

  const topRisks = (riskSummary.items ?? []).slice(0, 4);

  return (
    <div className="overview-dashboard">
      <Space direction="vertical" size="large" style={{ width: '100%' }}>
        <PageHeader
          title="运营总览"
          description="快速查看任务、风险、资产与队列状态，便于从单一入口跳转到详细视图"
          breadcrumbs={[{ label: '运营', path: '/' }, { label: '总览' }]}
          extra={
            <Space>
              <Button type="primary" onClick={() => navigate('/tasks')}>
                创建任务
              </Button>
              <Button onClick={() => navigate('/audit')}>查看审计</Button>
            </Space>
          }
        />

        <Row gutter={16}>
          {STAT_METRICS.map((metric) => (
            <Col xs={24} md={6} key={metric.key}>
              {loadingTasks ? (
                <Card className="overview-stat-card" variant="borderless">
                  <Skeleton active paragraph={false} />
                </Card>
              ) : (
                <OverviewStatCard
                  title={metric.title}
                  tone={metric.tone}
                  value={taskStats[metric.key]}
                  series={metricSeries[metric.key]}
                  trend={metricTrends[metric.key]}
                />
              )}
            </Col>
          ))}
        </Row>

        <Row gutter={16}>
          <Col xs={24} md={12}>
            <Card title="风险摘要" extra={<Link to="/risks">查看全部</Link>}>
              {loadingRisk ? (
                <Skeleton active />
              ) : (
                <List
                  dataSource={topRisks}
                  locale={{ emptyText: '暂无风险事件' }}
                  renderItem={(item) => (
                    <List.Item>
                      <Space direction="vertical" size={0}>
                        <Space>
                          <Text strong>{item.task_type}</Text>
                          <Tag color={item.status === 'failed' ? 'error' : item.status === 'running' ? 'processing' : 'default'}>
                            {item.status}
                          </Tag>
                        </Space>
                        <Text type="secondary">
                          {item.scenario_id ?? '未关联场景'} · {item.completed_at ? new Date(item.completed_at).toLocaleString() : '—'}
                        </Text>
                      </Space>
                    </List.Item>
                  )}
                />
              )}
            </Card>
          </Col>
          <Col xs={24} md={12}>
            <Card title="资产摘要" extra={<Link to="/assets">资产视图</Link>}>
              {loadingAssets ? (
                <Skeleton active />
              ) : (
                <Row gutter={16}>
                  <Col span={8}>
                    <Statistic title="在线" value={assetSummary?.totals.online ?? 0} />
                  </Col>
                  <Col span={8}>
                    <Statistic title="离线" value={assetSummary?.totals.offline ?? 0} />
                  </Col>
                  <Col span={8}>
                    <Statistic title="高风险" value={assetSummary?.totals.critical ?? 0} />
                  </Col>
                </Row>
              )}
            </Card>
          </Col>
        </Row>

        <Card title="快捷入口">
          <List
            grid={{ gutter: 16, column: 2 }}
            dataSource={quickLinks}
            locale={{ emptyText: '暂无可访问的入口' }}
            renderItem={(item) => (
              <List.Item key={item.to}>
                <Card hoverable className="quick-link-card">
                  <Space direction="vertical" size={4}>
                    <Text strong>{item.title}</Text>
                    <Text className="quick-link-meta">{item.description}</Text>
                    <Link className="quick-link-action" to={item.to}>
                      进入
                    </Link>
                  </Space>
                </Card>
              </List.Item>
            )}
          />
        </Card>
      </Space>
    </div>
  );
}

interface TrendInfo {
  direction: 'up' | 'down' | 'flat';
  label: string;
}

type AggregatedStats = Record<StatMetricKey, number>;

interface OverviewStatCardProps {
  title: string;
  tone: StatTone;
  value: number;
  series: number[];
  trend: TrendInfo;
}

function OverviewStatCard({ title, tone, value, series, trend }: OverviewStatCardProps) {
  const chartData = series.length > 0 ? series : [0, 0];
  const chartColor = STAT_TONE_CHART_COLOR[tone];

  return (
    <Card className="overview-stat-card" variant="borderless">
      <Statistic title={title} value={value} valueStyle={{ color: STAT_TONE_VALUE_COLOR[tone] }} />
      <div className="overview-stat-card__chart">
        <Sparkline data={chartData} color={chartColor} />
      </div>
      <div className={`stat-trend stat-trend--${trend.direction}`}>
        {trend.direction === 'up' ? (
          <ArrowUpOutlined />
        ) : trend.direction === 'down' ? (
          <ArrowDownOutlined />
        ) : (
          <MinusOutlined />
        )}
        <span>{trend.label}</span>
      </div>
      <Text type="secondary" className="stat-range">
        近 7 天趋势
      </Text>
    </Card>
  );
}

interface SparklineProps {
  data: number[];
  color: string;
}

function Sparkline({ data, color }: SparklineProps) {
  const gradientId = useId();
  const points = useMemo(() => {
    const safeData = data.length > 1 ? data : [data[0] ?? 0, data[0] ?? 0];
    const max = Math.max(...safeData);
    const min = Math.min(...safeData);
    const range = max - min || 1;
    return safeData.map((value, index) => {
      const x = (index / (safeData.length - 1)) * SPARKLINE_WIDTH;
      const normalizedY = (value - min) / range;
      return {
        x,
        y: SPARKLINE_HEIGHT - normalizedY * SPARKLINE_HEIGHT,
      };
    });
  }, [data]);

  if (points.length === 0) {
    return null;
  }

  const linePath = points
    .map((point, index) => `${index === 0 ? 'M' : 'L'} ${point.x.toFixed(2)} ${point.y.toFixed(2)}`)
    .join(' ');
  const lastPoint = points[points.length - 1];
  const firstPoint = points[0];
  const areaPath = `${linePath} L ${lastPoint.x.toFixed(2)} ${SPARKLINE_HEIGHT} L ${firstPoint.x.toFixed(2)} ${SPARKLINE_HEIGHT} Z`;

  return (
    <svg
      width="100%"
      height={SPARKLINE_HEIGHT}
      viewBox={`0 0 ${SPARKLINE_WIDTH} ${SPARKLINE_HEIGHT}`}
      preserveAspectRatio="none"
      role="presentation"
    >
      <defs>
        <linearGradient id={gradientId} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor={color} stopOpacity="0.35" />
          <stop offset="100%" stopColor={color} stopOpacity="0" />
        </linearGradient>
      </defs>
      <path d={areaPath} fill={`url(#${gradientId})`} stroke="none" />
      <path d={linePath} fill="none" stroke={color} strokeWidth={1.5} />
    </svg>
  );
}

function aggregateTaskStats(summary: TaskListSummary | undefined, tasks: Task[]): AggregatedStats {
  if (summary) {
    const byStatus = summary.by_status ?? {};
    return {
      total: summary.total ?? tasks.length,
      running: (byStatus.running ?? 0) + (byStatus.leased ?? 0),
      pending: byStatus.pending ?? 0,
      failed: byStatus.failed ?? 0,
    };
  }

  return tasks.reduce<AggregatedStats>(
    (acc, task) => {
      acc.total += 1;
      if (task.status === 'running' || task.status === 'leased') acc.running += 1;
      if (task.status === 'failed') acc.failed += 1;
      if (task.status === 'pending') acc.pending += 1;
      return acc;
    },
    { total: 0, running: 0, failed: 0, pending: 0 }
  );
}

function buildMetricSeries(tasks: Task[]): Record<StatMetricKey, number[]> {
  const bucketCount = 7;
  const now = dayjs();
  const buckets = Array.from({ length: bucketCount }, (_, index) => {
    const start = now.subtract(bucketCount - index - 1, 'day').startOf('day');
    const end = start.add(1, 'day');
    return { start, end };
  });

  const initialSeries = STAT_METRICS.reduce<Record<StatMetricKey, number[]>>((acc, metric) => {
    acc[metric.key] = new Array(bucketCount).fill(0);
    return acc;
  }, {} as Record<StatMetricKey, number[]>);

  tasks.forEach((task) => {
    const createdAt = dayjs(task.created_at);
    if (!createdAt.isValid()) return;
    const bucketIndex = buckets.findIndex(
      ({ start, end }) => (createdAt.isAfter(start) || createdAt.isSame(start)) && createdAt.isBefore(end)
    );
    if (bucketIndex === -1) return;
    STAT_METRICS.forEach((metric) => {
      if (metric.match(task)) {
        initialSeries[metric.key][bucketIndex] += 1;
      }
    });
  });

  return initialSeries;
}

function calculateAllTrends(seriesMap: Record<StatMetricKey, number[]>): Record<StatMetricKey, TrendInfo> {
  return STAT_METRICS.reduce<Record<StatMetricKey, TrendInfo>>((acc, metric) => {
    acc[metric.key] = calculateTrend(seriesMap[metric.key]);
    return acc;
  }, {} as Record<StatMetricKey, TrendInfo>);
}

function calculateTrend(series: number[]): TrendInfo {
  if (!series || series.length < 2) {
    return { direction: 'flat', label: '较昨日 --' };
  }
  const current = series[series.length - 1] ?? 0;
  const previous = series[series.length - 2] ?? 0;

  if (previous === 0 && current === 0) {
    return { direction: 'flat', label: '较昨日 0%' };
  }
  if (previous === 0) {
    return { direction: 'up', label: '较昨日 +100%' };
  }

  const change = ((current - previous) / previous) * 100;
  const rounded = Math.round(change * 10) / 10;
  const direction = rounded > 0 ? 'up' : rounded < 0 ? 'down' : 'flat';
  const formatted = `${rounded > 0 ? '+' : ''}${rounded.toFixed(1)}%`;
  return {
    direction,
    label: `较昨日 ${direction === 'flat' ? '0%' : formatted}`,
  };
}
