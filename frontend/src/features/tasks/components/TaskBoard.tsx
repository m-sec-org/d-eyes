import type { Task, TaskListSummary } from '@/services/types';
import { Card, Col, Row, Skeleton, Statistic } from 'antd';
import { ArrowUpOutlined, ArrowDownOutlined } from '@ant-design/icons';

interface TaskBoardProps {
  tasks: Task[];
  loading?: boolean;
  summary?: TaskListSummary;
}

const PLACEHOLDER = Array.from({ length: 4 });

export function TaskBoard({ tasks, loading = false, summary }: TaskBoardProps) {
  const stats = summary
    ? {
        total: summary.total ?? 0,
        running: (summary.by_status?.running ?? 0) + (summary.by_status?.leased ?? 0),
        pending: summary.by_status?.pending ?? 0,
        failed: summary.by_status?.failed ?? 0,
      }
    : tasks.reduce(
        (acc, task) => {
          const status = task.status;
          acc.total += 1;
          if (status === 'failed') acc.failed += 1;
          if (status === 'running' || status === 'leased') acc.running += 1;
          if (status === 'pending') acc.pending += 1;
          return acc;
        },
        { total: 0, running: 0, pending: 0, failed: 0 }
      );

  if (loading) {
    return (
      <Row gutter={16} style={{ marginBottom: 16 }}>
        {PLACEHOLDER.map((_, index) => (
          <Col xs={24} md={6} key={index}>
            <Card variant="borderless">
              <Skeleton active paragraph={false} title={{ width: '60%' }} />
            </Card>
          </Col>
        ))}
      </Row>
    );
  }

  return (
    <Row gutter={16} style={{ marginBottom: 16 }}>
      <Col xs={24} md={6}>
        <Card variant="borderless">
          <Statistic title="任务总数" value={stats.total} valueStyle={{ fontWeight: 600 }} />
        </Card>
      </Col>
      <Col xs={24} md={6}>
        <Card variant="borderless">
          <Statistic
            title="运行中"
            value={stats.running}
            prefix={<ArrowUpOutlined style={{ color: '#13c2c2' }} />}
          />
        </Card>
      </Col>
      <Col xs={24} md={6}>
        <Card variant="borderless">
          <Statistic
            title="待执行"
            value={stats.pending}
            prefix={<ArrowUpOutlined style={{ color: '#faad14' }} />}
          />
        </Card>
      </Col>
      <Col xs={24} md={6}>
        <Card variant="borderless">
          <Statistic
            title="失败"
            value={stats.failed}
            prefix={<ArrowDownOutlined style={{ color: '#ff4d4f' }} />}
          />
        </Card>
      </Col>
    </Row>
  );
}
