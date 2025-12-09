import './PlaybookConsole.css';
import { useEffect, useMemo, useState } from 'react';
import useSWR from 'swr';
import { Button, Card, Empty, Form, Input, List, message, Space, Tag, Timeline, Typography } from 'antd';
import { PageHeader } from '@/components/layout/PageHeader';
import { CodeBlock } from '@/components/CodeBlock';
import { createPlaybook, listPlaybooks, activatePlaybook, runPlaybook, listPlaybookRuns } from '@/services/api/playbooks';
import type { Playbook, PlaybookRun } from '@/services/types';

const { TextArea } = Input;
const { Title, Paragraph } = Typography;

const defaultTrigger = `{
  "type": "behavior.anomaly",
  "filter": {
    "severity": "high"
  }
}`;

const defaultActions = `[
  {
    "type": "notify",
    "target": "slack://sec-ops"
  },
  {
    "type": "task.dispatch",
    "task_type": "respond",
    "payload": {
      "profile": "containment"
    }
  }
]`;

const defaultRollback = `[
  {
    "type": "notify",
    "target": "slack://sec-ops",
    "metadata": {
      "channel": "rollback"
    }
  }
]`;

const statusColor: Record<string, string> = {
  draft: 'default',
  active: 'green',
  paused: 'orange',
};

const formHints = {
  trigger: '包含 type/filter/criteria 等字段，使用 JSON 表达触发条件。',
  actions: '数组形式，可包含 notify / task.dispatch 等动作。',
  rollback: '可选数组，用于失败后的补偿动作。',
  approvals: '格式：角色:秒数，例如 security.lead:1800。',
  conditions: '每行一个表达式，例如 severity == "high"。',
  payload: '当手动触发 Playbook 时，可自定义 payload JSON。',
};

const jsonValidator = (label: string) => ({
  validator(_: unknown, value: string) {
    if (!value || !value.trim()) {
      return Promise.resolve();
    }
    try {
      JSON.parse(value);
      return Promise.resolve();
    } catch {
      return Promise.reject(new Error(`${label} 必须是合法 JSON`));
    }
  },
});

function safeParse(value: string, fallback: unknown) {
  if (!value.trim()) return fallback;
  try {
    return JSON.parse(value);
  } catch (error) {
    throw new Error('JSON 解析失败: ' + (error as Error).message);
  }
}

function parseKeyValueLines(input: string): Record<string, string> | undefined {
  if (!input.trim()) return undefined;
  const result: Record<string, string> = {};
  input
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean)
    .forEach((line) => {
      const [key, ...rest] = line.split('=');
      if (key && rest.length) {
        result[key.trim()] = rest.join('=').trim();
      }
    });
  return Object.keys(result).length > 0 ? result : undefined;
}

export function PlaybookConsole() {
  const [messageApi, contextHolder] = message.useMessage();
  const [form] = Form.useForm();
  const [runForm] = Form.useForm();
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const {
    data: playbooks,
    mutate: refreshPlaybooks,
  } = useSWR<Playbook[]>('playbooks', () => listPlaybooks(100));

  useEffect(() => {
    if (!selectedId && playbooks && playbooks.length > 0) {
      setSelectedId(playbooks[0].id);
    }
  }, [playbooks, selectedId]);

  const selectedPlaybook = useMemo(() => playbooks?.find((item) => item.id === selectedId), [playbooks, selectedId]);

  const { data: runs, mutate: refreshRuns } = useSWR<PlaybookRun[]>
    (selectedId ? ['playbook-runs', selectedId] : null, () => listPlaybookRuns(selectedId ?? '', 25));

  const handleCreate = async () => {
    try {
      const values = await form.validateFields();
      const payload = {
        name: values.name,
        description: values.description,
        trigger: safeParse(values.trigger, {}),
        conditions: values.conditions?.split('\n').filter((line: string) => line.trim().length > 0),
        approvals: values.approvals
          ?.split('\n')
          .map((line: string) => line.trim())
          .filter(Boolean)
          .map((line) => {
            const [role, timeout] = line.split(':');
            return { role: role.trim(), timeout: timeout ? Number(timeout.trim()) : undefined };
          }),
        actions: safeParse(values.actions, []),
        rollback: values.rollback ? safeParse(values.rollback, []) : undefined,
      };
      await createPlaybook(payload);
      form.resetFields();
      await refreshPlaybooks();
      messageApi.success('Playbook 已创建');
    } catch (error) {
      messageApi.error((error as Error).message);
    }
  };

  const handleActivate = async (status: string) => {
    if (!selectedId) return;
    try {
      await activatePlaybook(selectedId, status);
      await refreshPlaybooks();
      messageApi.success(status === 'active' ? '已激活' : '已暂停');
    } catch (error) {
      messageApi.error('操作失败: ' + (error as Error).message);
    }
  };

  const handleRun = async () => {
    if (!selectedId) return;
    try {
      const values = await runForm.validateFields();
      await runPlaybook(selectedId, {
        type: values.type,
        attributes: parseKeyValueLines(values.attributes),
        data: values.payload ? safeParse(values.payload, {}) : undefined,
      });
      runForm.resetFields();
      await refreshRuns();
      messageApi.success('已触发 Playbook');
    } catch (error) {
      messageApi.error((error as Error).message);
    }
  };

  return (
    <div className="playbook-console">
      {contextHolder}
      <PageHeader
        title="Playbook 自动化控制台"
        description="创建/激活 Playbook，监控执行历史并处理响应动作"
        breadcrumbs={[{ label: '治理', path: '/settings' }, { label: 'Playbooks' }]}
        extra={
          <Space>
            <Button onClick={() => refreshPlaybooks()} size="small">
              刷新列表
            </Button>
            {selectedPlaybook && (
              <Button
                type="default"
                size="small"
                onClick={() => handleActivate(selectedPlaybook.status === 'active' ? 'paused' : 'active')}
              >
                {selectedPlaybook.status === 'active' ? '暂停' : '激活'}
              </Button>
            )}
          </Space>
        }
      />

      <div className="playbook-grid">
        <Card title="Playbook 列表" className="playbook-card" styles={{ body: { padding: 0 } }}>
          <List
            dataSource={playbooks ?? []}
            renderItem={(item) => (
              <List.Item className={item.id === selectedId ? 'selected' : ''} onClick={() => setSelectedId(item.id)}>
                <div className="playbook-list-item">
                  <div>
                    <strong>{item.name}</strong>
                    <Paragraph type="secondary" ellipsis={{ rows: 2 }}>
                      {item.description || '—'}
                    </Paragraph>
                  </div>
                  <Tag color={statusColor[item.status] ?? 'default'}>{item.status?.toUpperCase()}</Tag>
                </div>
              </List.Item>
            )}
          />
          {!playbooks?.length && <Empty description="暂无 Playbook" style={{ margin: '2rem 0' }} />}
        </Card>

        <Card title="新建 Playbook" className="playbook-card">
          <Form layout="vertical" form={form} initialValues={{ trigger: defaultTrigger, actions: defaultActions, rollback: defaultRollback }}>
            <Form.Item name="name" label="名称" rules={[{ required: true, message: '请输入名称' }]}>
              <Input placeholder="例如：恶意样本隔离" />
            </Form.Item>
            <Form.Item name="description" label="描述">
              <Input placeholder="简要说明 Playbook 作用" />
            </Form.Item>
            <Form.Item
              name="trigger"
              label="触发器 JSON"
              extra={<span className="playbook-form-hint">{formHints.trigger}</span>}
              rules={[
                { required: true, message: '请输入触发器配置' },
                jsonValidator('触发器 JSON'),
              ]}
            >
              <TextArea rows={4} spellCheck={false} />
            </Form.Item>
            <Form.Item
              name="conditions"
              label="条件（每行一个表达式）"
              extra={<span className="playbook-form-hint">{formHints.conditions}</span>}
            >
              <TextArea rows={2} placeholder={'agent.labels.env == "prod"'} spellCheck={false} />
            </Form.Item>
            <Form.Item
              name="approvals"
              label="审批链（示例：security.lead:1800）"
              extra={<span className="playbook-form-hint">{formHints.approvals}</span>}
            >
              <TextArea rows={2} placeholder="security.lead:1800" spellCheck={false} />
            </Form.Item>
            <Form.Item
              name="actions"
              label="动作 JSON"
              extra={<span className="playbook-form-hint">{formHints.actions}</span>}
              rules={[
                { required: true, message: '请输入动作配置' },
                jsonValidator('动作 JSON'),
              ]}
            >
              <TextArea rows={5} spellCheck={false} />
            </Form.Item>
            <Form.Item
              name="rollback"
              label="回滚动作 JSON"
              extra={<span className="playbook-form-hint">{formHints.rollback}</span>}
              rules={[jsonValidator('回滚动作 JSON')]}
            >
              <TextArea rows={3} spellCheck={false} />
            </Form.Item>
            <Button type="primary" onClick={handleCreate} block>
              创建 Playbook
            </Button>
          </Form>
        </Card>
      </div>

      <div className="playbook-details">
        <Card title="Playbook 详情" className="playbook-card">
          {selectedPlaybook ? (
            <div className="playbook-detail-pane">
              <div className="playbook-detail-row">
                <Title level={4}>{selectedPlaybook.name}</Title>
                <Tag color={statusColor[selectedPlaybook.status] ?? 'default'}>{selectedPlaybook.status?.toUpperCase()}</Tag>
              </div>
              <Paragraph type="secondary">{selectedPlaybook.description || '暂无描述'}</Paragraph>
              <div className="playbook-detail-grid">
                <CodeBlock value={selectedPlaybook.trigger} title="触发器" data-testid="playbook-trigger-block" />
                <div>
                  <strong>条件</strong>
                  {selectedPlaybook.conditions?.length ? (
                    <ul>
                      {selectedPlaybook.conditions.map((cond) => (
                        <li key={cond}>{cond}</li>
                      ))}
                    </ul>
                  ) : (
                    <span className="muted">无</span>
                  )}
                </div>
              </div>
              <CodeBlock value={selectedPlaybook.actions} title="动作" />
              {selectedPlaybook.rollback && selectedPlaybook.rollback.length > 0 && <CodeBlock value={selectedPlaybook.rollback} title="回滚" />}
              <div>
                <strong>审批链</strong>
                {selectedPlaybook.approvals?.length ? (
                  <Space wrap>
                    {selectedPlaybook.approvals.map((apr, idx) => (
                      <Tag key={`${apr.role}-${idx}`}>{apr.role + (apr.timeout ? ` (${apr.timeout}s)` : '')}</Tag>
                    ))}
                  </Space>
                ) : (
                  <span className="muted">无</span>
                )}
              </div>
            </div>
          ) : (
            <Empty description="请选择 Playbook" />
          )}
        </Card>

        <Card title="手动触发" className="playbook-card">
          {selectedPlaybook ? (
            <Form layout="vertical" form={runForm} initialValues={{ type: selectedPlaybook.trigger?.type ?? 'behavior.anomaly' }}>
              <Form.Item name="type" label="事件类型" rules={[{ required: true, message: '请输入事件类型' }]}>
                <Input />
              </Form.Item>
              <Form.Item
                name="attributes"
                label="属性（key=value，一行一个）"
                extra={<span className="playbook-form-hint">示例：severity=high</span>}
              >
                <TextArea rows={3} placeholder="severity=high" spellCheck={false} />
              </Form.Item>
              <Form.Item
                name="payload"
                label="Payload JSON"
                extra={<span className="playbook-form-hint">{formHints.payload}</span>}
                rules={[jsonValidator('Payload JSON')]}
              >
                <TextArea rows={3} placeholder="{}" spellCheck={false} />
              </Form.Item>
              <Button type="primary" onClick={handleRun} block>
                触发 Playbook
              </Button>
            </Form>
          ) : (
            <Empty description="请选择 Playbook" />
          )}
        </Card>

        <Card title="执行记录" className="playbook-card">
          {runs && runs.length > 0 ? (
            <Timeline
              mode="left"
              items={runs.map((run) => ({
                label: new Date(run.created_at).toLocaleString(),
                color: run.status === 'succeeded' ? 'green' : run.status === 'failed' ? 'red' : 'blue',
                children: (
                  <div>
                    <div>
                      <strong>{run.status.toUpperCase()}</strong> {run.trigger_type}
                    </div>
                    {run.steps?.length ? (
                      <ul>
                        {run.steps.slice(0, 3).map((step) => (
                          <li key={step.name}>
                            {step.name}: {step.status}
                          </li>
                        ))}
                        {run.steps.length > 3 && <li>…</li>}
                      </ul>
                    ) : (
                      <span className="muted">暂无步骤数据</span>
                    )}
                  </div>
                ),
              }))}
            />
          ) : (
            <Empty description="暂无执行记录" />
          )}
        </Card>
      </div>
    </div>
  );
}
