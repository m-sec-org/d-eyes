import { useState } from 'react';
import useSWR from 'swr';
import dayjs from 'dayjs';
import { listAuditEvents } from '@/services/api/audit';
import { OperationTimeline } from '@/components/OperationTimeline';

export function AuditLogView() {
  const { data, isLoading, mutate } = useSWR('audit-events', listAuditEvents);
  const [filter, setFilter] = useState('all');

  const filtered = data?.items.filter((event) => (filter === 'all' ? true : event.resource.startsWith(filter))) ?? [];

  return (
    <div className="audit-log-view">
      <section className="section-heading">
        <div>
          <h1>审计日志</h1>
          <p className="muted">记录系统关键操作，支持过滤与导出</p>
        </div>
        <div className="actions">
          <button type="button" className="ghost" onClick={() => mutate()}>
            刷新
          </button>
          <button type="button" className="primary">
            导出 JSON
          </button>
        </div>
      </section>

      <section className="card">
        <div className="filter-row">
          <select value={filter} onChange={(event) => setFilter(event.target.value)}>
            <option value="all">全部资源</option>
            <option value="task">任务操作</option>
            <option value="system">系统配置</option>
            <option value="audit">审计导出</option>
          </select>
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
