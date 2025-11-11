import { useMemo } from 'react';
import { Card, Col, List, Row, Skeleton, Space, Statistic, Tag, Typography, Button } from 'antd';
import { Link, useNavigate } from 'react-router-dom';
import { PageHeader } from '@/components/layout/PageHeader';
import { useTasksData } from '../tasks/hooks/useTasksData';
import { useAssets } from '../assets/hooks/useAssets';
import { useRiskSummary } from '../risks/hooks/useRiskSummary';

const { Text } = Typography;

const OVERVIEW_FILTERS = {
  status: 'all',
  search: '',
} as const;

const QUICK_LINKS = [
  { title: '任务指挥中心', description: '查看队列与筛选任务', to: '/tasks' },
  { title: '风险监控', description: 'Respond/Baseline 风险摘要', to: '/risks' },
  { title: '资产视图', description: '资产 inventory 与标签管理', to: '/assets' },
  { title: '命令队列', description: '调度/排队与 Agent 运行状态', to: '/queues', role: 'admin' },
];

export function OverviewDashboard() {
  const navigate = useNavigate();
  const { tasks, isLoading: loadingTasks } = useTasksData(OVERVIEW_FILTERS);
  const { summary: assetSummary, isLoading: loadingAssets } = useAssets();
  const { summary: riskSummary, isLoading: loadingRisk } = useRiskSummary('respond');

  const taskStats = useMemo(() => {
    return tasks.reduce(
      (acc, task) => {
        acc.total += 1;
        if (task.status === 'running' || task.status === 'leased') acc.running += 1;
        if (task.status === 'failed') acc.failed += 1;
        if (task.status === 'pending') acc.pending += 1;
        return acc;
      },
      { total: 0, running: 0, failed: 0, pending: 0 }
    );
  }, [tasks]);

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
          <Col xs={24} md={6}>
            <Card variant="borderless">
              {loadingTasks ? (
                <Skeleton active paragraph={false} />
              ) : (
                <Statistic title="任务总数" value={taskStats.total} />
              )}
            </Card>
          </Col>
          <Col xs={24} md={6}>
            <Card variant="borderless">
              {loadingTasks ? (
                <Skeleton active paragraph={false} />
              ) : (
                <Statistic title="运行中" value={taskStats.running} valueStyle={{ color: '#13c2c2' }} />
              )}
            </Card>
          </Col>
          <Col xs={24} md={6}>
            <Card variant="borderless">
              {loadingTasks ? (
                <Skeleton active paragraph={false} />
              ) : (
                <Statistic title="待执行" value={taskStats.pending} valueStyle={{ color: '#faad14' }} />
              )}
            </Card>
          </Col>
          <Col xs={24} md={6}>
            <Card variant="borderless">
              {loadingTasks ? (
                <Skeleton active paragraph={false} />
              ) : (
                <Statistic title="失败告警" value={taskStats.failed} valueStyle={{ color: '#ff4d4f' }} />
              )}
            </Card>
          </Col>
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
            dataSource={QUICK_LINKS}
            renderItem={(item) => (
              <List.Item>
                <Card hoverable>
                  <Space direction="vertical" size={4}>
                    <Text strong>{item.title}</Text>
                    <Text type="secondary">{item.description}</Text>
                    <Link to={item.to}>进入</Link>
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
