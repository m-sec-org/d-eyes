import dayjs from 'dayjs';
import { useMemo, useState, type ReactNode } from 'react';
import { Column } from '@ant-design/plots';
import {
  Button,
  Card,
  Col,
  Empty,
  List,
  Row,
  Segmented,
  Skeleton,
  Space,
  Statistic,
  Tag,
  Typography,
  theme,
} from 'antd';
import {
  ReloadOutlined,
  DownloadOutlined,
  ArrowDownOutlined,
  ArrowUpOutlined,
  MinusOutlined,
  AlertOutlined,
  ThunderboltOutlined,
  DashboardOutlined,
} from '@ant-design/icons';
import { useRiskSummary } from './hooks/useRiskSummary';
import { PageHeader } from '@/components/layout/PageHeader';

const STATUS_LABELS: Record<string, string> = {
  running: '运行中',
  failed: '失败',
  succeeded: '成功',
  pending: '待执行',
  queued: '排队中',
};

const STATUS_COLORS: Record<string, string> = {
  running: 'processing',
  failed: 'error',
  succeeded: 'success',
  pending: 'default',
  queued: 'warning',
};

const CHART_COLOR_MAP: Record<string, string> = {
  运行中: '#177ddc',
  失败: '#f5222d',
  成功: '#13a8a8',
  待执行: '#faad14',
  排队中: '#722ed1',
};

const REPORT_OPTIONS = [
  { label: 'Respond 作战', value: 'respond' },
  { label: 'Baseline 巡检', value: 'baseline' },
];

const { Text } = Typography;

export function RiskDashboard() {
  const [reportType, setReportType] = useState<'respond' | 'baseline'>('respond');
  const { summary, isLoading, refresh } = useRiskSummary(reportType);
  const { token } = theme.useToken();

  const chartData = useMemo(() => {
    return Object.entries(summary.status ?? {}).map(([status, value]) => ({
      status: STATUS_LABELS[status] ?? status,
      value,
    }));
  }, [summary.status]);

  const hasChartData = chartData.some((item) => item.value > 0);

  const columnConfig = useMemo(
    () => ({
      data: chartData,
      xField: 'status',
      yField: 'value',
      seriesField: 'status',
      columnWidthRatio: 0.55,
      color: (datum: { status: string }) => CHART_COLOR_MAP[datum.status] ?? '#177ddc',
      label: { position: 'top', style: { fontSize: 12 } },
      legend: {
        position: 'top',
      },
      tooltip: {
        showMarkers: false,
        formatter: (datum: { status: string; value: number }) => ({
          name: datum.status,
          value: `${datum.value} 次`,
        }),
      },
      interactions: [{ type: 'active-region' }],
      xAxis: { label: { autoRotate: false } },
      yAxis: {
        label: {
          formatter: (value: string) => `${value}`,
        },
      },
      columnStyle: {
        radius: [4, 4, 0, 0],
      },
    }),
    [chartData]
  );

  const statCards: StatCardConfig[] = [
    {
      title: '总风险事件',
      value: summary.totals[reportType] ?? 0,
      color: token.colorPrimary,
      icon: <DashboardOutlined style={{ color: token.colorPrimary }} />,
      trend: summary.trends?.totals?.[reportType],
    },
    {
      title: '失败 / 高危',
      value: summary.status.failed ?? 0,
      color: token.colorError,
      icon: <AlertOutlined style={{ color: token.colorError }} />,
      trend: summary.trends?.status?.failed,
    },
    {
      title: '处理中',
      value: summary.status.running ?? 0,
      color: token.colorWarning,
      icon: <ThunderboltOutlined style={{ color: token.colorWarning }} />,
      trend: summary.trends?.status?.running,
    },
  ];

  const trendPeriod = summary.trends?.period ?? '较昨日';

  return (
    <div className="risk-dashboard">
      <Space direction="vertical" size="large" style={{ width: '100%' }}>
        <PageHeader
          title="风险监控"
          description="查看 respond/baseline 任务产生的风险摘要与趋势"
          breadcrumbs={[
            { label: '洞察', path: '/risks' },
            { label: '风险中心' },
          ]}
          extra={
            <Space wrap>
              <Segmented
                value={reportType}
                onChange={(value) => setReportType(value as 'respond' | 'baseline')}
                options={REPORT_OPTIONS}
              />
              <Button icon={<ReloadOutlined />} onClick={() => refresh()} loading={isLoading}>
                刷新
              </Button>
              <Button icon={<DownloadOutlined />} type="primary" ghost>
                导出风险报表
              </Button>
            </Space>
          }
        />

        <Row gutter={16}>
          {statCards.map((card) => (
            <Col xs={24} md={8} key={card.title}>
              <Card variant="borderless">
                {isLoading ? (
                  <Skeleton active paragraph={false} title={{ width: '60%' }} />
                ) : (
                  <Space direction="vertical" size={4}>
                    <Space align="center" size={8}>
                      {card.icon}
                      <Statistic
                        title={card.title}
                        value={card.value}
                        valueStyle={{ fontWeight: 600, color: card.color }}
                      />
                    </Space>
                    <TrendText trend={card.trend} period={trendPeriod} />
                  </Space>
                )}
              </Card>
            </Col>
          ))}
        </Row>

        <Card title="状态趋势" extra={<Button type="link" onClick={() => refresh()}>重新拉取</Button>}>
          {isLoading ? (
            <Skeleton active />
          ) : hasChartData ? (
            <Column {...columnConfig} height={260} />
          ) : (
            <Empty description="暂无风险数据" />
          )}
        </Card>

        <Card title="风险时间线">
          <List
            loading={isLoading}
            dataSource={summary.items}
            locale={{ emptyText: '暂无风险事件' }}
            renderItem={(item) => (
              <List.Item>
                <Space direction="vertical" size={0}>
                  <Space>
                    <Text strong>{item.task_type}</Text>
                    <Tag color={STATUS_COLORS[item.status] ?? 'default'}>
                      {STATUS_LABELS[item.status] ?? item.status}
                    </Tag>
                  </Space>
                  <Text type="secondary">
                    {dayjs(item.completed_at).format('MM-DD HH:mm')} · {item.scenario_id ?? '未关联场景'}
                  </Text>
                </Space>
                <Text type="secondary">#{item.task_id.slice(0, 8)}</Text>
              </List.Item>
            )}
          />
        </Card>
      </Space>
    </div>
  );
}

interface StatCardConfig {
  title: string;
  value: number;
  color?: string;
  icon?: ReactNode;
  trend?: TrendMetric;
}

interface TrendMetric {
  delta: number;
  trend?: 'up' | 'down' | 'flat';
}

function TrendText({ trend, period }: { trend?: TrendMetric; period: string }) {
  const direction = trend?.trend ?? (trend ? (trend.delta > 0 ? 'up' : trend.delta < 0 ? 'down' : 'flat') : 'flat');
  const isFlat = direction === 'flat';

  let color = 'var(--ant-color-text-secondary)';
  if (direction === 'up') color = 'var(--ant-color-success)';
  if (direction === 'down') color = 'var(--ant-color-error)';

  const icon =
    direction === 'up' ? (
      <ArrowUpOutlined />
    ) : direction === 'down' ? (
      <ArrowDownOutlined />
    ) : (
      <MinusOutlined />
    );

  const deltaText = trend ? `${trend.delta > 0 ? '+' : ''}${trend.delta}%` : '0%';

  return (
    <Text style={{ color }}>
      {icon} {period} {isFlat ? '—' : ''} {deltaText}
    </Text>
  );
}
