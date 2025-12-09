import { useMemo, useState } from 'react';
import useSWR from 'swr';
import { message } from 'antd';

import { listAgents, updateAgentLabels, type Agent } from '@/services/api/agents';
import { AppBulkToolbar, AppCard, AppFormSection, AppTable, Button, Select, Textarea, TextInput } from '@/components/ui';

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
  const [bulkSelection, setBulkSelection] = useState<string[]>([]);
  const [bulkLabels, setBulkLabels] = useState('');
  const [bulkUpdating, setBulkUpdating] = useState(false);

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
    const parsed = parseLabelInput(labelsDraft);
    await updateAgentLabels(editing.id, parsed);
    setEditing(null);
    await mutate();
  };

  const selectedAgents = useMemo(
    () => agents.filter((agent) => bulkSelection.includes(agent.id)),
    [agents, bulkSelection]
  );

  const toggleAgentSelection = (agentId: string, checked: boolean) => {
    setBulkSelection((prev) => {
      if (checked) {
        return prev.includes(agentId) ? prev : [...prev, agentId];
      }
      return prev.filter((id) => id !== agentId);
    });
  };

  const toggleAllAgents = (checked: boolean) => {
    if (checked) {
      setBulkSelection(agents.map((agent) => agent.id));
    } else {
      setBulkSelection([]);
    }
  };

  const handleBulkUpdate = async () => {
    if (selectedAgents.length === 0) {
      message.info('请选择需要更新的 Agent');
      return;
    }
    const parsed = parseLabelInput(bulkLabels);
    if (Object.keys(parsed).length === 0) {
      message.warning('请输入 `key:value` 格式的标签');
      return;
    }
    setBulkUpdating(true);
    try {
      for (const agent of selectedAgents) {
        await updateAgentLabels(agent.id, { ...(agent.labels ?? {}), ...parsed });
      }
      message.success(`已更新 ${selectedAgents.length} 个 Agent 标签`);
      setBulkSelection([]);
      setBulkLabels('');
      await mutate();
    } catch (error) {
      console.error(error);
      message.error('批量更新失败，请稍后重试');
    } finally {
      setBulkUpdating(false);
    }
  };

  const allSelected = agents.length > 0 && bulkSelection.length === agents.length;

  return (
    <div className="stack">
      <AppCard
        title="Agent 节点"
        description="实时了解 Agent 在线状态、能力与标签。"
        actions={
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
        }
      >
        <AppTable>
          <table>
            <thead>
              <tr>
                <th>
                  <input
                    type="checkbox"
                    aria-label="选择全部 Agent"
                    checked={allSelected}
                    onChange={(event) => toggleAllAgents(event.target.checked)}
                  />
                </th>
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
                  <td>
                    <input
                      type="checkbox"
                      aria-label={`选择 Agent ${agent.name ?? agent.id}`}
                      checked={bulkSelection.includes(agent.id)}
                      onChange={(event) => toggleAgentSelection(agent.id, event.target.checked)}
                    />
                  </td>
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
        </AppTable>
        {bulkSelection.length > 0 && (
          <AppBulkToolbar
            summary={
              <>
                <strong>已选 {bulkSelection.length} 个 Agent</strong>
                <span className="muted">批量更新标签</span>
              </>
            }
            actions={
              <>
                <Textarea
                  rows={2}
                  placeholder="key:value，每行一个"
                  value={bulkLabels}
                  onChange={(event) => setBulkLabels(event.target.value)}
                />
                <Button type="primary" size="sm" onClick={handleBulkUpdate} loading={bulkUpdating}>
                  应用标签
                </Button>
                <Button size="sm" onClick={() => setBulkSelection([])}>
                  清除选择
                </Button>
              </>
            }
          />
        )}
      </AppCard>

      {editing && (
        <AppFormSection
          as="section"
          title={`编辑 ${editing.name ?? editing.id} 标签`}
          description="使用 `key:value` 形式，每行一个条目，或使用逗号分隔。"
        >
          <Textarea rows={4} value={labelsDraft} onChange={(e) => setLabelsDraft(e.target.value)} />
          <div className="actions">
            <Button type="button" variant="primary" onClick={handleSaveLabels}>
              保存
            </Button>
            <Button type="button" variant="ghost" onClick={() => setEditing(null)}>
              取消
            </Button>
          </div>
        </AppFormSection>
      )}
    </div>
  );
}

function parseLabelInput(input: string) {
  const parsed: Record<string, string> = {};
  input
    .split(/\n|,/)
    .map((line) => line.trim())
    .filter(Boolean)
    .forEach((entry) => {
      const [key, value] = entry.split(':');
      if (key && value) {
        parsed[key.trim()] = value.trim();
      }
    });
  return parsed;
}
