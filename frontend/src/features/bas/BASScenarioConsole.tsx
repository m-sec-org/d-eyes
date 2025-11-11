import { useMemo, useState } from 'react';
import useSWR from 'swr';

import {
  activateBASScenario,
  approveBASScenario,
  createBASScenario,
  deactivateBASScenario,
  listBASScenarios,
} from '@/services/api/basScenarios';
import type { BASResourceLimit, BASScenario, BASScenarioStep } from '@/services/types';
import { Button, Checkbox, FormField, Textarea, TextInput } from '@/components/ui';

interface DraftStep {
  id: string;
  name: string;
  action: string;
  requireSandbox: boolean;
  timeoutSeconds: number;
}

interface DraftScenario {
  name: string;
  description: string;
  tags: string;
  boundaries: string;
  requiresApproval: boolean;
  resourceLimits: BASResourceLimit;
  steps: DraftStep[];
}

const defaultDraft: DraftScenario = {
  name: '',
  description: '',
  tags: '',
  boundaries: '',
  requiresApproval: true,
  resourceLimits: {
    max_targets: 32,
    max_parallel_steps: 2,
    max_duration_minutes: 60,
    max_cpu_percent: 80,
  },
  steps: [],
};

const defaultStep: DraftStep = {
  id: randomId(),
  name: '',
  action: '',
  requireSandbox: false,
  timeoutSeconds: 60,
};

export function BASScenarioConsole() {
  const { data: scenarios, mutate, isLoading } = useSWR('bas-scenarios', listBASScenarios);
  const [form, setForm] = useState<DraftScenario>(defaultDraft);
  const [stepDraft, setStepDraft] = useState<DraftStep>(defaultStep);
  const [submitting, setSubmitting] = useState(false);

  const sortedScenarios = useMemo(() => {
    if (!scenarios) return [];
    return [...scenarios].sort((a, b) => a.name.localeCompare(b.name));
  }, [scenarios]);

  const resetForm = () => {
    setForm(defaultDraft);
    setStepDraft(defaultStep);
  };

  const handleAddStep = () => {
    if (!stepDraft.name.trim() || !stepDraft.action.trim()) {
      return;
    }
    setForm((prev) => ({
      ...prev,
      steps: [
        ...prev.steps,
        {
          ...stepDraft,
          id: randomId(),
        },
      ],
    }));
    setStepDraft({
      id: randomId(),
      name: '',
      action: '',
      requireSandbox: false,
      timeoutSeconds: 60,
    });
  };

  const handleStepReorder = (index: number, direction: 'up' | 'down') => {
    setForm((prev) => {
      const steps = [...prev.steps];
      const target = direction === 'up' ? index - 1 : index + 1;
      if (target < 0 || target >= steps.length) {
        return prev;
      }
      [steps[index], steps[target]] = [steps[target], steps[index]];
      return { ...prev, steps };
    });
  };

  const handleRemoveStep = (index: number) => {
    setForm((prev) => ({
      ...prev,
      steps: prev.steps.filter((_, idx) => idx !== index),
    }));
  };

  const handleSubmit = async (event: React.FormEvent) => {
    event.preventDefault();
    if (!form.name.trim() || form.steps.length === 0) return;
    setSubmitting(true);
    try {
      await createBASScenario({
        name: form.name,
        description: form.description,
        tags: parseList(form.tags),
        network_boundaries: parseList(form.boundaries),
        requires_approval: form.requiresApproval,
        resource_limits: {
          max_targets: safeNumber(form.resourceLimits.max_targets),
          max_parallel_steps: safeNumber(form.resourceLimits.max_parallel_steps),
          max_duration_minutes: safeNumber(form.resourceLimits.max_duration_minutes),
          max_cpu_percent: safeNumber(form.resourceLimits.max_cpu_percent),
        },
        steps: form.steps.map((step, index) => ({
          id: step.id,
          name: step.name,
          action: step.action,
          order: index + 1,
          require_sandbox: step.requireSandbox,
          timeout_seconds: step.timeoutSeconds,
        })) as BASScenarioStep[],
      });
      resetForm();
      await mutate();
    } finally {
      setSubmitting(false);
    }
  };

  const handleApprove = async (scenario: BASScenario) => {
    const approver = window.prompt('请输入审批人名称', 'secops.lead');
    if (!approver) return;
    await approveBASScenario(scenario.id, approver, 'console approve');
    await mutate();
  };

  const handleToggle = async (scenario: BASScenario) => {
    if (scenario.status === 'active') {
      await deactivateBASScenario(scenario.id);
    } else {
      await activateBASScenario(scenario.id);
    }
    await mutate();
  };

  return (
    <div className="stack">
      <section className="card">
        <header className="section-header">
          <div>
            <h2>BAS 场景管理</h2>
            <p className="muted">创建、审批并控制 BAS 场景执行边界。</p>
          </div>
          {isLoading && <span className="muted">加载中…</span>}
        </header>
        <div className="scenario-grid">
          {sortedScenarios.map((scenario) => (
            <article key={scenario.id} className="scenario-card">
              <header>
                <div>
                  <h3>{scenario.name}</h3>
                  <p className="muted">{scenario.description || '—'}</p>
                  <ScenarioStatusBadge status={scenario.status} />
                </div>
                <div className="scenario-actions">
                  {scenario.requires_approval && scenario.status !== 'approved' && scenario.status !== 'active' && (
                    <Button type="button" variant="ghost" size="sm" onClick={() => handleApprove(scenario)}>
                      审批
                    </Button>
                  )}
                  <Button type="button" variant="ghost" size="sm" onClick={() => handleToggle(scenario)}>
                    {scenario.status === 'active' ? '停用' : '启用'}
                  </Button>
                </div>
              </header>
              <div>
                <strong>步骤</strong>
                <ol>
                  {scenario.steps?.map((step) => (
                    <li key={step.id}>
                      {step.name} · {step.action}{' '}
                      {step.require_sandbox && <span className="muted">(强制 Sandbox)</span>}
                    </li>
                  ))}
                </ol>
              </div>
              <footer>
                <div className="muted">
                  边界：{scenario.network_boundaries?.length ? scenario.network_boundaries.join(', ') : '未指定'}
                </div>
                <div className="muted">
                  资源：目标 {scenario.resource_limits?.max_targets ?? '—'} · 并发{' '}
                  {scenario.resource_limits?.max_parallel_steps ?? '—'} · 时长{' '}
                  {scenario.resource_limits?.max_duration_minutes ?? '—'} 分钟
                </div>
              </footer>
            </article>
          ))}
          {!sortedScenarios.length && !isLoading && <p className="muted">暂无场景，创建第一个吧。</p>}
        </div>
      </section>

      <section className="card">
        <h2>新建场景</h2>
        <form className="form-grid" onSubmit={handleSubmit}>
          <FormField label="场景名称" required>
            <TextInput value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} required />
          </FormField>
          <FormField label="描述">
            <Textarea rows={2} value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} />
          </FormField>
          <FormField label="标签（逗号分隔）" hint="示例：respond,high-risk">
            <TextInput value={form.tags} onChange={(e) => setForm({ ...form, tags: e.target.value })} />
          </FormField>
          <FormField label="网络边界（逗号分隔）" hint="如 DMZ,prod-subnet">
            <TextInput value={form.boundaries} onChange={(e) => setForm({ ...form, boundaries: e.target.value })} />
          </FormField>
          <Checkbox
            checked={form.requiresApproval}
            onChange={(e) => setForm({ ...form, requiresApproval: e.target.checked })}
            label="需要审批后才能执行"
          />

          <div className="resource-grid">
            <FormField label="目标上限">
              <TextInput
                type="number"
                min={1}
                value={form.resourceLimits.max_targets ?? ''}
                onChange={(e) =>
                  setForm({
                    ...form,
                    resourceLimits: { ...form.resourceLimits, max_targets: Number(e.target.value) },
                  })
                }
              />
            </FormField>
            <FormField label="并发步骤">
              <TextInput
                type="number"
                min={1}
                value={form.resourceLimits.max_parallel_steps ?? ''}
                onChange={(e) =>
                  setForm({
                    ...form,
                    resourceLimits: { ...form.resourceLimits, max_parallel_steps: Number(e.target.value) },
                  })
                }
              />
            </FormField>
            <FormField label="最长执行（分钟）">
              <TextInput
                type="number"
                min={1}
                value={form.resourceLimits.max_duration_minutes ?? ''}
                onChange={(e) =>
                  setForm({
                    ...form,
                    resourceLimits: { ...form.resourceLimits, max_duration_minutes: Number(e.target.value) },
                  })
                }
              />
            </FormField>
            <FormField label="CPU 上限（%）">
              <TextInput
                type="number"
                min={10}
                max={100}
                value={form.resourceLimits.max_cpu_percent ?? ''}
                onChange={(e) =>
                  setForm({
                    ...form,
                    resourceLimits: { ...form.resourceLimits, max_cpu_percent: Number(e.target.value) },
                  })
                }
              />
            </FormField>
          </div>

          <div className="steps-editor">
            <h3>步骤编排</h3>
            <div className="step-draft">
              <TextInput
                placeholder="步骤名称"
                value={stepDraft.name}
                onChange={(e) => setStepDraft((prev) => ({ ...prev, name: e.target.value }))}
              />
              <TextInput
                placeholder="Action"
                value={stepDraft.action}
                onChange={(e) => setStepDraft((prev) => ({ ...prev, action: e.target.value }))}
              />
              <TextInput
                type="number"
                min={10}
                placeholder="超时（秒）"
                value={stepDraft.timeoutSeconds}
                onChange={(e) =>
                  setStepDraft((prev) => ({ ...prev, timeoutSeconds: Number(e.target.value) || 0 }))
                }
              />
              <Checkbox
                label="Sandbox"
                checked={stepDraft.requireSandbox}
                onChange={(e) => setStepDraft((prev) => ({ ...prev, requireSandbox: e.target.checked }))}
              />
              <Button type="button" variant="ghost" size="sm" onClick={handleAddStep}>
                添加步骤
              </Button>
            </div>

            <ol>
              {form.steps.map((step, index) => (
                <li key={step.id} className="step-row">
                  <div>
                    <strong>
                      {index + 1}. {step.name}
                    </strong>
                    <div className="muted">
                      {step.action} · 超时 {step.timeoutSeconds}s · {step.requireSandbox ? 'Sandbox' : '原地'}
                    </div>
                  </div>
                  <div className="step-actions">
                    <Button type="button" variant="ghost" size="sm" onClick={() => handleStepReorder(index, 'up')}>
                      ↑
                    </Button>
                    <Button type="button" variant="ghost" size="sm" onClick={() => handleStepReorder(index, 'down')}>
                      ↓
                    </Button>
                    <Button type="button" variant="ghost-danger" size="sm" onClick={() => handleRemoveStep(index)}>
                      删除
                    </Button>
                  </div>
                </li>
              ))}
            </ol>
          </div>

          <div className="actions">
            <Button type="submit" variant="primary" disabled={submitting || !form.name || form.steps.length === 0}>
              保存场景
            </Button>
            <Button type="button" variant="ghost" onClick={resetForm}>
              重置
            </Button>
          </div>
        </form>
      </section>
    </div>
  );
}

function ScenarioStatusBadge({ status }: { status: BASScenario['status'] }) {
  const color =
    status === 'active'
      ? 'status-success'
      : status === 'approved'
        ? 'status-info'
        : status === 'disabled'
          ? 'status-muted'
          : 'status-warning';
  return (
    <span className={`tag ${color}`} aria-label={`status-${status}`}>
      {status}
    </span>
  );
}

function parseList(input: string) {
  return input
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean);
}

function safeNumber(value?: number) {
  if (typeof value !== 'number' || Number.isNaN(value) || value <= 0) return undefined;
  return value;
}

function randomId() {
  return Math.random().toString(36).slice(2, 10);
}
