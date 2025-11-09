import { useMemo } from 'react';
import useSWR from 'swr';
import { listAuditEvents } from '@/services/api/audit';
import { useTaskEventStore } from '@/store/taskEvents';

interface TimelineItem {
  id: string;
  title: string;
  timestamp: string;
  type: 'task' | 'audit';
  meta?: string;
}

export function OperationTimeline() {
  const { data: auditData } = useSWR('audit-events', listAuditEvents);
  const taskEvents = useTaskEventStore((state) => state.events);

  const timeline = useMemo<TimelineItem[]>(() => {
    const taskItems: TimelineItem[] = taskEvents.map((event) => ({
      id: `task-${event.task_id}-${event.updated_at}-${event.event}`,
      title: `任务 ${event.event}`,
      timestamp: event.updated_at,
      type: 'task',
      meta: event.task_type,
    }));

    const auditItems: TimelineItem[] =
      auditData?.items.map((event) => ({
        id: `audit-${event.id}`,
        title: `${event.actor} ${event.action}`,
        timestamp: event.timestamp,
        type: 'audit',
        meta: event.resource,
      })) ?? [];

    return [...taskItems, ...auditItems]
      .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
      .slice(0, 8);
  }, [auditData, taskEvents]);

  return (
    <ul className="timeline">
      {timeline.map((item) => (
        <li key={item.id}>
          <div>
            <strong>{item.title}</strong>
            {item.meta && <span className="timeline-meta"> · {item.meta}</span>}
          </div>
          <time>{new Date(item.timestamp).toLocaleString()}</time>
        </li>
      ))}
      {timeline.length === 0 && <li className="muted">暂无操作记录</li>}
    </ul>
  );
}
