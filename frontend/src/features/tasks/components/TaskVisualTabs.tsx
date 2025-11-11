import { Card, List, Tabs, Tag } from 'antd';

import type { TaskVisual } from '@/services/types';

interface TaskVisualTabsProps {
  visuals?: TaskVisual[];
}

export function TaskVisualTabs({ visuals = [] }: TaskVisualTabsProps) {
  if (!visuals.length) return null;

  const tabItems = visuals.map((visual) => ({
    key: visual.visual_type,
    label: prettifyLabel(visual.visual_type),
    children: renderVisualContent(visual),
  }));

  return (
    <section>
      <h3 style={{ marginBottom: 12 }}>结果可视化</h3>
      <Tabs items={tabItems} />
    </section>
  );
}

function renderVisualContent(visual: TaskVisual) {
  const payload = (visual.payload ?? {}) as Record<string, unknown>;

  switch (visual.visual_type) {
    case 'network_graph': {
      const nodes = Array.isArray(payload.nodes) ? (payload.nodes as Record<string, string>[]) : [];
      const edges = Array.isArray(payload.edges) ? (payload.edges as Record<string, string>[]) : [];
      return (
        <Card size="small">
          <p>
            节点 <strong>{nodes.length}</strong> · 连边 <strong>{edges.length}</strong>
          </p>
          <List
            size="small"
            dataSource={nodes}
            renderItem={(node) => (
              <List.Item>
                <span>{node.label ?? node.id}</span>
                {node.risk && <Tag color={riskColor(node.risk)}>{node.risk}</Tag>}
                <span className="muted">{node.kind}</span>
              </List.Item>
            )}
          />
        </Card>
      );
    }
    case 'file_risk': {
      const total = typeof payload.total_files === 'number' ? payload.total_files : 0;
      const riskCounts = (payload.risk_counts ?? {}) as Record<string, number>;
      const hits = Array.isArray(payload.top_hits) ? (payload.top_hits as Record<string, string>[]) : [];
      return (
        <Card size="small">
          <p>
            扫描文件 <strong>{total}</strong> 个
          </p>
          <div className="risk-counts">
            {Object.entries(riskCounts).map(([level, count]) => (
              <Tag key={level} color={riskColor(level)}>
                {level}: {count}
              </Tag>
            ))}
          </div>
          <List
            size="small"
            header="Top Hits"
            dataSource={hits.slice(0, 5)}
            renderItem={(hit) => (
              <List.Item>
                <div>
                  <div>{hit.path ?? '未命名文件'}</div>
                  <div className="muted">{hit.reason}</div>
                </div>
                {hit.risk && <Tag color={riskColor(hit.risk)}>{hit.risk}</Tag>}
              </List.Item>
            )}
          />
        </Card>
      );
    }
    case 'host_summary': {
      const hosts = Array.isArray(payload.hosts) ? (payload.hosts as Record<string, unknown>[]) : [];
      return (
        <Card size="small">
          <List
            size="small"
            dataSource={hosts}
            renderItem={(host) => (
              <List.Item>
                <div>
                  <strong>{(host.hostname as string) ?? (host.id as string) ?? '未知主机'}</strong>
                  <div className="muted">
                    {typeof host.ip === 'string' ? host.ip : '—'} ·{' '}
                    {typeof host.os === 'string' ? host.os : '未知系统'} · 风险{' '}
                    {typeof host.risk_score === 'number' || typeof host.risk_score === 'string'
                      ? host.risk_score
                      : '—'}
                  </div>
                </div>
              </List.Item>
            )}
          />
        </Card>
      );
    }
    default:
      return (
        <Card size="small">
          <pre style={{ whiteSpace: 'pre-wrap' }}>{JSON.stringify(payload, null, 2)}</pre>
        </Card>
      );
  }
}

function prettifyLabel(value: string) {
  switch (value) {
    case 'network_graph':
      return '网络连通';
    case 'file_risk':
      return '文件风险';
    case 'host_summary':
      return '主机摘要';
    default:
      return value;
  }
}

function riskColor(level: string) {
  switch (level) {
    case 'critical':
      return 'magenta';
    case 'high':
      return 'red';
    case 'medium':
      return 'orange';
    case 'low':
      return 'blue';
    default:
      return 'default';
  }
}
