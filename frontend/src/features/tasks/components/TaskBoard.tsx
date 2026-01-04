import './TaskBoard.css';
import { useMemo, useState } from 'react';
import dayjs from 'dayjs';
import type { Task, TaskListSummary } from '@/services/types';
import { Card, Col, Row, Skeleton, Statistic, Segmented, Select, Typography } from 'antd';
import { ArrowUpOutlined, ArrowDownOutlined } from '@ant-design/icons';
import { AppStickyToolbar } from '@/components/ui';

interface TaskBoardProps {
  tasks: Task[];
  loading?: boolean;
  summary?: TaskListSummary;
}

const PLACEHOLDER = Array.from({ length: 4 });
type TimeFilter = 'all' | '1h' | '6h' | '24h';
type DisplayMode = 'count' | 'ratio';

const TIME_FILTER_OPTIONS = [
  { label: '全部', value: 'all' },
  { label: '1 小时', value: '1h' },
  { label: '6 小时', value: '6h' },
  { label: '24 小时', value: '24h' },
];

const DISPLAY_MODE_OPTIONS = [
  { label: '数量', value: 'count' },
  { label: '占比', value: 'ratio' },
];

export function TaskBoard({ tasks, loading = false, summary }: TaskBoardProps) {
  const [timeFilter, setTimeFilter] = useState<TimeFilter>('all');
  const [displayMode, setDisplayMode] = useState<DisplayMode>('count');

  const filteredTasks = useMemo(() => {
    if (timeFilter === 'all') return tasks;
    const hours = timeFilter === '1h' ? 1 : timeFilter === '6h' ? 6 : 24;
    const threshold = dayjs().subtract(hours, 'hour');
    return tasks.filter((task) => dayjs(task.updated_at).isAfter(threshold));
  }, [tasks, timeFilter]);

  const stats = useMemo(() => {
    if (timeFilter === 'all' && summary) {
      return {
        total: summary.total ?? 0,
        running: (summary.by_status?.running ?? 0) + (summary.by_status?.leased ?? 0),
        pending: summary.by_status?.pending ?? 0,
        failed: summary.by_status?.failed ?? 0,
      };
    }
    return filteredTasks.reduce(
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
  }, [filteredTasks, summary, timeFilter]);

  const dataSource = [
    { key: 'total', title: '任务总数', value: stats.total, tone: 'neutral' as const },
    { key: 'running', title: '运行中', value: stats.running, tone: 'info' as const },
    { key: 'pending', title: '待执行', value: stats.pending, tone: 'warning' as const },
    { key: 'failed', title: '失败', value: stats.failed, tone: 'danger' as const },
  ];

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
    <section className="task-board">
      <AppStickyToolbar
        headline={<Typography.Title level={4}>任务健康概览</Typography.Title>}
        description="实时观察任务运行态势，可切换展示模式与时间窗口"
        actions={
          <>
            <Segmented
              options={DISPLAY_MODE_OPTIONS}
              value={displayMode}
              onChange={(value) => setDisplayMode(value as DisplayMode)}
            />
            <Select
              value={timeFilter}
              onChange={(value) => setTimeFilter(value as TimeFilter)}
              style={{ width: 140 }}
              options={TIME_FILTER_OPTIONS}
            />
          </>
        }
      />
      <Row gutter={24} className="task-board-grid">
        {dataSource.map((item) => (
          <Col xs={24} md={6} key={item.key}>
            <Card variant="borderless" className="task-board-card tone-neutral">
              <Statistic
                title={item.title}
                value={
                  displayMode === 'ratio' && stats.total > 0
                    ? Number(((item.value / stats.total) * 100).toFixed(1))
                    : item.value
                }
                suffix={displayMode === 'ratio' ? '%' : undefined}
                valueStyle={{ fontWeight: 600 }}
                prefix={
                  item.key === 'failed'
                    ? <ArrowDownOutlined style={{ color: '#ff4d4f' }} />
                    : item.key === 'running'
                      ? <ArrowUpOutlined style={{ color: '#13c2c2' }} />
                      : item.key === 'pending'
                        ? <ArrowUpOutlined style={{ color: '#faad14' }} />
                        : undefined
                }
              />
            </Card>
          </Col>
        ))}
      </Row>
    </section>
  );
}
