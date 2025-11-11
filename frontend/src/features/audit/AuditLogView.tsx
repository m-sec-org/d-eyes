import { useState } from 'react';
import useSWR from 'swr';
import dayjs from 'dayjs';
import { listAuditEvents } from '@/services/api/audit';
import type { AuditEvent } from '@/services/types';
import { OperationTimeline } from '@/components/OperationTimeline';
import { Button, TextInput } from '@/components/ui';

export function AuditLogView() {
  const [actor, setActor] = useState('');
  const [resource, setResource] = useState('');
  const [action, setAction] = useState('');
  const [limit, setLimit] = useState(50);
  const { data, isLoading, mutate } = useSWR(['audit-events', actor, resource, action, limit], () =>
    listAuditEvents({ actor, resource, action, limit })
  );

  const filtered = data?.items ?? [];

  return (
    <div className="audit-log-view">
      <section className="section-heading">
        <div>
          <h1>审计日志</h1>
          <p className="muted">记录系统关键操作，支持过滤与导出</p>
        </div>
        <div className="actions">
          <Button type="button" variant="ghost" onClick={() => mutate()}>
            刷新
          </Button>
          <Button type="button" variant="primary" onClick={() => downloadJSON(filtered)}>
            导出 JSON
          </Button>
        </div>
      </section>

      <section className="card">
        <div className="filter-row">
          <TextInput placeholder="操作人" value={actor} onChange={(e) => setActor(e.target.value)} />
          <TextInput placeholder="资源关键词" value={resource} onChange={(e) => setResource(e.target.value)} />
          <TextInput placeholder="行为关键词" value={action} onChange={(e) => setAction(e.target.value)} />
          <TextInput type="number" min={10} max={500} value={limit} onChange={(e) => setLimit(Number(e.target.value) || 50)} />
        </div>
        {isLoading ? (
          <div>加载中...</div>
        ) : (
          <div className="table">
            <div className="table-row header">
              <span>时间</span>
              <span>操作人</span>
              <span>角色</span>
              <span>行为</span>
              <span>资源</span>
            </div>
            {filtered.map((event) => (
              <div key={event.id} className="table-row">
                <span>{dayjs(event.timestamp).format('MM-DD HH:mm')}</span>
                <span>{event.actor}</span>
                <span className="muted">{event.role}</span>
                <span>{event.action}</span>
                <span>{event.resource}</span>
              </div>
            ))}
            {filtered.length === 0 && <div className="empty">暂无审计记录</div>}
          </div>
        )}
      </section>

      <section className="card">
        <header className="card-header">
          <h2>最近操作</h2>
          <small>同步任务事件与审计数据</small>
        </header>
        <OperationTimeline />
      </section>
    </div>
  );
}

function downloadJSON(events: AuditEvent[]) {
  const payload = JSON.stringify(events, null, 2);
  const blob = new Blob([payload], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = `audit-${Date.now()}.json`;
  anchor.click();
  URL.revokeObjectURL(url);
}
