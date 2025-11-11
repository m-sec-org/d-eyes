import dayjs from 'dayjs';
import { useMemo, useState } from 'react';
import { Column } from '@ant-design/plots';
import { Button, Card, Col, Empty, List, Row, Segmented, Skeleton, Space, Statistic, Tag, Typography } from 'antd';
import { ReloadOutlined, DownloadOutlined } from '@ant-design/icons';
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
  运行中: '#13c2c2',
  失败: '#ff4d4f',
  成功: '#52c41a',
  待执行: '#faad14',
  排队中: '#1677ff',
};

const REPORT_OPTIONS = [
  { label: 'Respond 作战', value: 'respond' },
  { label: 'Baseline 巡检', value: 'baseline' },
];

const { Text } = Typography;

export function RiskDashboard() {
  const [reportType, setReportType] = useState<'respond' | 'baseline'>('respond');
  const { summary, isLoading, refresh } = useRiskSummary(reportType);

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
      columnWidthRatio: 0.55,
      colorField: 'status',
      color: (datum: { status: string }) => CHART_COLOR_MAP[datum.status] ?? '#1677ff',
      label: { position: 'inside', style: { fill: '#fff', fontSize: 12 } },
      tooltip: { showMarkers: false },
      interactions: [{ type: 'active-region' }],
      xAxis: { label: { autoRotate: false } },
    }),
    [chartData]
  );

  const statCards = [
    { title: '总风险事件', value: summary.totals[reportType] ?? 0, color: undefined },
    { title: '失败 / 高危', value: summary.status.failed ?? 0, color: '#ff4d4f' },
    { title: '处理中', value: summary.status.running ?? 0, color: '#13c2c2' },
  ];

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
                  <Statistic
                    title={card.title}
                    value={card.value}
                    valueStyle={{ fontWeight: 600, color: card.color }}
                  />
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
