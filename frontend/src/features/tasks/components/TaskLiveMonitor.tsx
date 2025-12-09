import { useEffect, useMemo, useRef, useState } from 'react';
import dayjs from 'dayjs';
import type { Task, TaskEvent } from '@/services/types';
import { useTaskEventStore } from '@/store/taskEvents';
import { performTaskAction } from '@/services/api/taskActions';
import { AppStickyToolbar, AppSummaryCard, Button, Select } from '@/components/ui';
import { cn } from '@/utils/cn';
import type { QueueSummary } from '@/services/api/queues';
import type { QueueStreamStatus } from '@/store/queueSummary';
import './TaskLiveMonitor.css';

interface TaskLiveMonitorProps {
  tasks: Task[];
  queueSummary?: QueueSummary;
  queueStatus?: QueueStreamStatus;
}

type TimeWindowValue = 'all' | 5 | 10 | 30;

interface OverflowSegment {
  id: string;
  label: string;
  timestamp: number;
  total: number;
  danger: number;
  warning: number;
  info: number;
}

const ROW_HEIGHT = 52;
const OVERSCAN = 4;
const DEFAULT_VISIBLE_LIMIT = 150;
const TIME_WINDOWS: ReadonlyArray<{ label: string; value: TimeWindowValue }> = [
  { label: '全部', value: 'all' },
  { label: '5 分钟', value: 5 },
  { label: '10 分钟', value: 10 },
  { label: '30 分钟', value: 30 },
];
const VISIBLE_LIMIT_OPTIONS = [100, 150, 200];

function formatTimestamp(value: string) {
  return dayjs(value).format('HH:mm:ss');
}

function toMinuteBucket(event: TaskEvent) {
  const ts = dayjs(event.updated_at);
  return {
    bucket: ts.startOf('minute').valueOf(),
    label: ts.format('MM-DD HH:mm'),
  };
}

export function TaskLiveMonitor({ tasks, queueSummary, queueStatus = 'connecting' }: TaskLiveMonitorProps) {
  const events = useTaskEventStore((state) => state.events);
  const status = useTaskEventStore((state) => state.status);
  const [selectedTaskId, setSelectedTaskId] = useState('');
  const [filterSeverity, setFilterSeverity] = useState('');
  const [timeWindow, setTimeWindow] = useState<TimeWindowValue>('all');
  const [visibleLimit, setVisibleLimit] = useState(DEFAULT_VISIBLE_LIMIT);
  const [frozen, setFrozen] = useState(false);
  const [pendingEvents, setPendingEvents] = useState(0);
  const [actionLoading, setActionLoading] = useState(false);
  const scrollRef = useRef<HTMLDivElement | null>(null);
  const [viewportHeight, setViewportHeight] = useState(360);
  const [scrollTop, setScrollTop] = useState(0);
  const previousCountRef = useRef(events.length);

  useEffect(() => {
    if (frozen) {
      if (events.length > previousCountRef.current) {
        setPendingEvents((prev) => prev + (events.length - previousCountRef.current));
      }
    } else {
      setPendingEvents(0);
      flushScrollTop(scrollRef.current);
    }
    previousCountRef.current = events.length;
  }, [events.length, frozen]);

  useEffect(() => {
    const node = scrollRef.current;
    if (!node) return;
    const measure = () => setViewportHeight(node.clientHeight || 360);
    measure();

    const handleResize = () => measure();
    window.addEventListener('resize', handleResize);
    let observer: ResizeObserver | null = null;
    if (typeof ResizeObserver !== 'undefined') {
      observer = new ResizeObserver(measure);
      observer.observe(node);
    }
    return () => {
      window.removeEventListener('resize', handleResize);
      observer?.disconnect();
    };
  }, [visibleLimit]);

  const filteredEvents = useMemo(() => {
    const threshold =
      timeWindow === 'all' ? null : Date.now() - Number(timeWindow) * 60 * 1000;
    return events.filter((event) => {
      if (selectedTaskId && event.task_id !== selectedTaskId) {
        return false;
      }
      if (filterSeverity && event.severity && event.severity !== filterSeverity) {
        return false;
      }
      if (threshold && new Date(event.updated_at).getTime() < threshold) {
        return false;
      }
      return true;
    });
  }, [events, selectedTaskId, filterSeverity, timeWindow]);

  const visibleEvents = useMemo(
    () => filteredEvents.slice(0, visibleLimit),
    [filteredEvents, visibleLimit]
  );
  const overflowEvents = useMemo(
    () => filteredEvents.slice(visibleLimit),
    [filteredEvents, visibleLimit]
  );

  const overflowSegments = useMemo<OverflowSegment[]>(() => {
    if (overflowEvents.length === 0) {
      return [];
    }
    const map = new Map<number, OverflowSegment>();
    overflowEvents.forEach((event) => {
      const { bucket, label } = toMinuteBucket(event);
      const existing =
        map.get(bucket) ??
        {
          id: `segment-${bucket}`,
          label,
          timestamp: bucket,
          total: 0,
          danger: 0,
          warning: 0,
          info: 0,
        };
      existing.total += 1;
      if (event.severity === 'danger') {
        existing.danger += 1;
      } else if (event.severity === 'warning') {
        existing.warning += 1;
      } else {
        existing.info += 1;
      }
      map.set(bucket, existing);
    });
    return Array.from(map.values()).sort((a, b) => b.timestamp - a.timestamp);
  }, [overflowEvents]);

  const severitySummary = useMemo(() => {
    return filteredEvents.reduce(
      (acc, event) => {
        if (event.severity === 'danger') acc.danger += 1;
        else if (event.severity === 'warning') acc.warning += 1;
        else acc.info += 1;
        return acc;
      },
      { danger: 0, warning: 0, info: 0 }
    );
  }, [filteredEvents]);

  const taskStatusSummary = useMemo(() => {
    return tasks.reduce<Record<string, number>>((acc, task) => {
      acc[task.status] = (acc[task.status] ?? 0) + 1;
      return acc;
    }, {});
  }, [tasks]);

  const totalRows = visibleEvents.length;
  const startIndex = Math.max(0, Math.floor(scrollTop / ROW_HEIGHT) - OVERSCAN);
  const endIndex = Math.min(
    totalRows,
    Math.ceil((scrollTop + viewportHeight) / ROW_HEIGHT) + OVERSCAN
  );
  const virtualRows = visibleEvents.slice(startIndex, endIndex);
  const offsetY = startIndex * ROW_HEIGHT;
  const tableHeight = totalRows * ROW_HEIGHT || ROW_HEIGHT;

  const lastAlert = filteredEvents.find(
    (event) => event.severity === 'danger' || event.severity === 'warning'
  );

  const handleScroll = () => {
    const node = scrollRef.current;
    if (!node) return;
    setScrollTop(node.scrollTop);
  };

  const handleAction = async (action: 'pause' | 'resume' | 'terminate') => {
    if (!selectedTaskId) return;
    setActionLoading(true);
    try {
      await performTaskAction(selectedTaskId, action);
    } finally {
      setActionLoading(false);
    }
  };

  const toggleFreeze = () => {
    setFrozen((prev) => !prev);
    if (!frozen) {
      setPendingEvents(0);
    }
  };

  const resumeFromFreeze = () => {
    setFrozen(false);
    setPendingEvents(0);
    flushScrollTop(scrollRef.current);
  };

  return (
    <section className="card task-live-monitor">
      <AppStickyToolbar
        className="task-live-monitor__toolbar"
        headline={
          <>
            <h2>任务指挥中心 · 实时监控</h2>
            <p className="muted">
              任务流状态：{status}{' '}
              {pendingEvents > 0 && frozen && (
                <span className="live-monitor-pending">新事件 +{pendingEvents}</span>
              )}
            </p>
            <p className="muted">
              队列流：{queueStatus} · 深度 {queueSummary?.queue_depth ?? '--'} · 运行 {queueSummary?.in_flight ?? '--'}
            </p>
            {queueSummary && (queueSummary.status_counts?.blocked ?? 0) > 0 && (
              <span className="live-monitor-alert danger">
                队列阻塞 {queueSummary.status_counts?.blocked} 个任务，请关注 QueueMonitor。
              </span>
            )}
          </>
        }
        actions={
          <>
            <Select
              value={timeWindow.toString()}
              aria-label="时间窗口"
              onChange={(e) =>
                setTimeWindow(e.target.value === 'all' ? 'all' : (Number(e.target.value) as TimeWindowValue))
              }
            >
              {TIME_WINDOWS.map((window) => (
                <option key={window.value} value={window.value}>
                  {window.label}
                </option>
              ))}
            </Select>
            <Select
              value={filterSeverity}
              onChange={(e) => setFilterSeverity(e.target.value)}
              aria-label="筛选严重级别"
            >
              <option value="">全部级别</option>
              <option value="info">Info</option>
              <option value="warning">Warning</option>
              <option value="danger">Danger</option>
            </Select>
            <Select
              value={selectedTaskId}
              onChange={(e) => setSelectedTaskId(e.target.value)}
              aria-label="筛选任务"
            >
              <option value="">全部任务</option>
              {tasks.map((task) => (
                <option key={task.id} value={task.id}>
                  {task.id.slice(0, 8)} · {task.type}
                </option>
              ))}
            </Select>
            <Select
              value={visibleLimit.toString()}
              aria-label="事件窗口大小"
              onChange={(e) => setVisibleLimit(Number(e.target.value))}
            >
              {VISIBLE_LIMIT_OPTIONS.map((size) => (
                <option key={size} value={size}>
                  最近 {size} 条
                </option>
              ))}
            </Select>
            <Button type="button" variant={frozen ? 'secondary' : 'ghost'} onClick={toggleFreeze}>
              {frozen ? '恢复实时' : '冻结视图'}
            </Button>
            {pendingEvents > 0 && frozen && (
              <Button type="button" variant="primary" size="sm" onClick={resumeFromFreeze}>
                查看 {pendingEvents} 条新事件
              </Button>
            )}
          </>
        }
      />

      <div className="live-monitor-summary">
        <div className="live-monitor-summary__grid">
          <AppSummaryCard label="总事件" value={filteredEvents.length} />
          <AppSummaryCard label="告警 (danger)" value={severitySummary.danger} tone="danger" />
          <AppSummaryCard label="告警 (warning)" value={severitySummary.warning} tone="warning" />
          <AppSummaryCard label="信息 (info)" value={severitySummary.info} tone="info" />
        </div>
        <div className="live-monitor-summary__grid">
          <AppSummaryCard label="运行中" value={taskStatusSummary.running ?? 0} tone="info" />
          <AppSummaryCard label="待调度" value={taskStatusSummary.pending ?? 0} tone="warning" />
          <AppSummaryCard label="失败" value={taskStatusSummary.failed ?? 0} tone="danger" />
          <AppSummaryCard label="成功" value={taskStatusSummary.succeeded ?? 0} tone="success" />
        </div>
      </div>

      {lastAlert && (
        <div className={cn('live-monitor-alert', lastAlert.severity)}>
          <strong>最新告警</strong>
          <span>
            {lastAlert.task_id.slice(0, 8)} · {lastAlert.message ?? lastAlert.event}
          </span>
        </div>
      )}

      <div className="task-live-monitor__controls">
        <Button
          type="button"
          variant="ghost"
          disabled={!selectedTaskId || actionLoading}
          onClick={() => handleAction('pause')}
        >
          暂停
        </Button>
        <Button
          type="button"
          variant="ghost"
          disabled={!selectedTaskId || actionLoading}
          onClick={() => handleAction('resume')}
        >
          恢复
        </Button>
        <Button
          type="button"
          variant="ghost-danger"
          disabled={!selectedTaskId || actionLoading}
          onClick={() => handleAction('terminate')}
        >
          终止
        </Button>
        <Button type="button" variant="ghost" onClick={() => (window.location.href = '/queues')}>
          查看命令队列
        </Button>
      </div>

      <div className="live-monitor-table" role="table" aria-rowcount={totalRows}>
        <div className="live-monitor-table__header" role="rowgroup">
          <div className="live-monitor-row live-monitor-row--header" role="row">
            <span role="columnheader">时间</span>
            <span role="columnheader">事件</span>
            <span role="columnheader">任务</span>
            <span role="columnheader">进度</span>
            <span role="columnheader">消息</span>
          </div>
        </div>
        <div
          className="live-monitor-virtual-body"
          role="rowgroup"
          ref={scrollRef}
          onScroll={handleScroll}
          data-testid="live-monitor-virtual-body"
        >
          <div style={{ height: tableHeight }}>
            <div style={{ transform: `translateY(${offsetY}px)` }}>
              {virtualRows.map((event, index) => (
                <div
                  key={`${event.task_id}-${event.updated_at}-${event.event}-${index}`}
                  className="live-monitor-row"
                  role="row"
                  data-testid="live-monitor-row"
                >
                  <span role="cell" className="mono">
                    {formatTimestamp(event.updated_at)}
                  </span>
                  <span role="cell">
                    <span
                      className={cn(
                        'tag',
                        event.severity === 'danger'
                          ? 'status-danger'
                          : event.severity === 'warning'
                          ? 'status-warning'
                          : 'status-info'
                      )}
                    >
                      {event.event}
                    </span>
                  </span>
                  <span role="cell" className="mono">
                    {event.task_id.slice(0, 8)}
                  </span>
                  <span role="cell">{typeof event.progress === 'number' ? `${event.progress}%` : '—'}</span>
                  <span role="cell">{event.message ?? event.action ?? '—'}</span>
                </div>
              ))}
            </div>
          </div>
          {totalRows === 0 && <div className="live-monitor-empty">暂无事件</div>}
        </div>
      </div>

      {overflowSegments.length > 0 && (
        <div className="live-monitor-overflow">
          <header>
            <strong>更早事件（{overflowEvents.length} 条）</strong>
            <span className="muted">已折叠为 {overflowSegments.length} 个 1 分钟时间段，可按需展开</span>
          </header>
          <div className="live-monitor-overflow__segments">
            {overflowSegments.map((segment) => (
              <div key={segment.id} className="live-monitor-overflow__segment">
                <div>
                  <strong>{segment.label}</strong>
                  <span className="muted"> · {segment.total} 条</span>
                </div>
                <div className="live-monitor-overflow__counts">
                  <span className="pill pill--danger">D {segment.danger}</span>
                  <span className="pill pill--warning">W {segment.warning}</span>
                  <span className="pill pill--info">I {segment.info}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </section>
  );
}

function flushScrollTop(node: HTMLDivElement | null) {
  if (!node) return;
  if (typeof node.scrollTo === 'function') {
    node.scrollTo({ top: 0 });
  } else {
    node.scrollTop = 0;
  }
}
