import { useMemo, useState } from 'react';
import useSWR from 'swr';

import { listAgents, updateAgentLabels, type Agent } from '@/services/api/agents';
import { Button, Select, Textarea, TextInput } from '@/components/ui';

const STATUS_OPTIONS = [
  { label: '全部', value: '' },
  { label: '在线', value: 'online' },
  { label: '离线', value: 'offline' },
];

export function AgentDirectory() {
  const [status, setStatus] = useState('');
  const [capability, setCapability] = useState('');
  const [tag, setTag] = useState('');
  const { data, mutate } = useSWR(['agents', status, capability, tag], () =>
    listAgents({ status, capability, tag })
  );
  const [editing, setEditing] = useState<Agent | null>(null);
  const [labelsDraft, setLabelsDraft] = useState('');

  const agents = useMemo(() => data ?? [], [data]);

  const handleOpenEditor = (agent: Agent) => {
    setEditing(agent);
    const pairs = Object.entries(agent.labels ?? {})
      .map(([key, value]) => `${key}:${value}`)
      .join('\n');
    setLabelsDraft(pairs);
  };

  const handleSaveLabels = async () => {
    if (!editing) return;
    const parsed: Record<string, string> = {};
    labelsDraft
      .split(/\n|,/)
      .map((line) => line.trim())
      .filter(Boolean)
      .forEach((entry) => {
        const [key, value] = entry.split(':');
        if (key && value) {
          parsed[key.trim()] = value.trim();
        }
      });
    await updateAgentLabels(editing.id, parsed);
    setEditing(null);
    await mutate();
  };

  return (
    <div className="stack">
      <section className="card">
        <header className="section-heading">
          <div>
            <h2>Agent 节点</h2>
            <p className="muted">实时了解 Agent 在线状态、能力与标签。</p>
          </div>
          <div className="actions">
            <Select value={status} onChange={(e) => setStatus(e.target.value)}>
              {STATUS_OPTIONS.map((option) => (
                <option key={option.value} value={option.value}>
                  {option.label}
                </option>
              ))}
            </Select>
            <TextInput placeholder="Capability" value={capability} onChange={(e) => setCapability(e.target.value)} />
            <TextInput placeholder="标签值" value={tag} onChange={(e) => setTag(e.target.value)} />
          </div>
        </header>
        <div className="table-wrapper">
          <table>
            <thead>
              <tr>
                <th>名称</th>
                <th>状态</th>
                <th>平台</th>
                <th>版本</th>
                <th>能力</th>
                <th>标签</th>
                <th>心跳</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {agents.map((agent) => (
                <tr key={agent.id}>
                  <td>{agent.name ?? agent.id}</td>
                  <td>
                    <span className={`tag ${agent.status === 'online' ? 'status-success' : 'status-muted'}`}>
                      {agent.status}
                    </span>
                  </td>
                  <td>{agent.platform ?? '—'}</td>
                  <td>{agent.version ?? '—'}</td>
                  <td>{agent.capabilities.join(', ') || '—'}</td>
                  <td>
                    {agent.labels && Object.keys(agent.labels).length > 0
                      ? Object.entries(agent.labels)
                          .map(([k, v]) => `${k}:${v}`)
                          .join(', ')
                      : '—'}
                  </td>
                  <td>{agent.last_heartbeat ? new Date(agent.last_heartbeat).toLocaleString() : '—'}</td>
                  <td>
                    <Button type="button" variant="ghost" size="sm" onClick={() => handleOpenEditor(agent)}>
                      标签
                    </Button>
                  </td>
                </tr>
              ))}
              {agents.length === 0 && (
                <tr>
                  <td colSpan={8} className="muted">
                    暂无数据
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </section>

      {editing && (
        <section className="card">
          <h3>编辑 {editing.name ?? editing.id} 标签</h3>
          <p className="muted">使用 `key:value` 形式，每行一个条目，或使用逗号分隔。</p>
          <Textarea rows={4} value={labelsDraft} onChange={(e) => setLabelsDraft(e.target.value)} />
          <div className="actions">
            <Button type="button" variant="primary" onClick={handleSaveLabels}>
              保存
            </Button>
            <Button type="button" variant="ghost" onClick={() => setEditing(null)}>
              取消
            </Button>
          </div>
        </section>
      )}
    </div>
  );
}
