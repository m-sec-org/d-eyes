import { useEffect, useMemo, useState } from 'react';
import useSWR from 'swr';

import {
  activateBASScenario,
  approveBASScenario,
  cloneBASScenario,
  createBASScenario,
  deactivateBASScenario,
  listBASScenarios,
  publishBASScenario,
} from '@/services/api/basScenarios';
import { listTasks } from '@/services/api/tasks';
import { createTask } from '@/services/api/taskActions';
import { getBASReport } from '@/services/api/basRuns';
import type {
  BASResourceLimit,
  BASRunReport,
  BASScenario,
  BASScenarioStep,
  Task,
  TaskListResponse,
} from '@/services/types';
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

const RUN_POLLING_STATES = new Set(['pending', 'leased', 'running']);

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
  const {
    data: runResponse,
    mutate: mutateRuns,
    isLoading: isRunsLoading,
  } = useSWR<TaskListResponse>('bas-runs', () => listTasks({ type: 'bas', limit: 15 }), {
    refreshInterval: 10000,
  });
  const [form, setForm] = useState<DraftScenario>(defaultDraft);
  const [stepDraft, setStepDraft] = useState<DraftStep>(defaultStep);
  const [submitting, setSubmitting] = useState(false);
  const basRuns = useMemo(() => (runResponse ?? []).filter((task) => task.type?.toLowerCase().startsWith('bas')), [runResponse]);
  const [selectedRunId, setSelectedRunId] = useState<string | null>(null);
  const selectedRun = basRuns.find((task) => task.id === selectedRunId) ?? null;
  const shouldPollReport = selectedRun ? RUN_POLLING_STATES.has(selectedRun.status) : false;
  const { data: runReport, isLoading: isReportLoading } = useSWR<BASRunReport>(
    selectedRunId ? ['bas-report', selectedRunId] : null,
    () => getBASReport(selectedRunId!),
    {
      refreshInterval: shouldPollReport ? 6000 : 0,
    }
  );

  const sortedScenarios = useMemo(() => {
    if (!scenarios) return [];
    return [...scenarios].sort((a, b) => a.name.localeCompare(b.name));
  }, [scenarios]);

  useEffect(() => {
    if (!selectedRunId && basRuns.length > 0) {
      setSelectedRunId(basRuns[0].id);
    }
  }, [basRuns, selectedRunId]);

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

  const handlePublish = async (scenario: BASScenario) => {
    const actor = window.prompt('请输入发布人', 'secops.lead');
    if (!actor) return;
    await publishBASScenario(scenario.id, actor);
    await mutate();
  };

  const handleClone = async (scenario: BASScenario) => {
    const name = window.prompt('复制后的场景名称', `${scenario.name}-copy`);
    if (!name) return;
    await cloneBASScenario(scenario.id, name, 'automation');
    await mutate();
  };

  const handleRunScenario = async (scenario: BASScenario) => {
    if (!['approved', 'active'].includes(scenario.status)) {
      window.alert('请先审批/启用该场景后再运行');
      return;
    }
    const profile = window.prompt('选择执行 Profile（默认 default）', 'default')?.trim() || 'default';
    try {
      await createTask({
        type: 'bas.advanced',
        profile,
        metadata: {
          scenario_id: scenario.id,
          required_capabilities: 'bas',
        },
        priority: 5,
      });
      await mutateRuns();
    } catch (error) {
      window.alert('调度任务失败，请稍后重试');
      console.error(error);
    }
  };

  const refreshRuns = async () => {
    await mutateRuns();
  };

  return (
    <div className="stack bas-workbench">
      <section className="card">
        <header className="section-header">
          <div>
            <h2>BAS 场景管理</h2>
            <p className="muted">创建、审批并控制 BAS 场景执行边界，并直接调度演练。</p>
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
                  <div className="scenario-tags">
                    <ScenarioStatusBadge status={scenario.status} />
                    <span className="tag status-muted">v{scenario.version ?? 1}</span>
                    {scenario.execution_plan?.mode && (
                      <span className="tag status-info">模式: {scenario.execution_plan.mode}</span>
                    )}
                  </div>
                </div>
                <div className="scenario-actions">
                  {scenario.requires_approval && scenario.status !== 'approved' && scenario.status !== 'active' && (
                    <Button type="button" variant="ghost" size="sm" onClick={() => handleApprove(scenario)}>
                      审批
                    </Button>
                  )}
                  {['draft', 'disabled'].includes(scenario.status) && (
                    <Button type="button" variant="ghost" size="sm" onClick={() => handlePublish(scenario)}>
                      发布
                    </Button>
                  )}
                  <Button type="button" variant="ghost" size="sm" onClick={() => handleClone(scenario)}>
                    克隆
                  </Button>
                  <Button type="button" variant="ghost" size="sm" onClick={() => handleRunScenario(scenario)}>
                    运行
                  </Button>
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
                {scenario.required_labels?.length && (
                  <div className="muted">标签要求：{scenario.required_labels.join(', ')}</div>
                )}
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

      <section className="card bas-run-panel">
        <header className="section-header">
          <div>
            <h2>BAS 执行队列</h2>
            <p className="muted">实时跟踪最近的 BAS 任务，对比成功率与失败点。</p>
          </div>
          <Button type="button" variant="ghost" size="sm" onClick={refreshRuns} disabled={isRunsLoading}>
            刷新
          </Button>
        </header>
        <div className="run-list">
          {basRuns.map((task) => (
            <button
              key={task.id}
              type="button"
              className={`run-item ${task.id === selectedRunId ? 'active' : ''}`}
              onClick={() => setSelectedRunId(task.id)}
            >
              <div className="run-item-header">
                <strong>{task.metadata?.scenario_name ?? '未知场景'}</strong>
                <span className={`run-status status-${statusClass(task.status)}`}>{translateStatus(task.status)}</span>
              </div>
              <div className="run-item-meta">
                #{task.id.slice(-6)} · {new Date(task.created_at).toLocaleString()}
              </div>
              <div className="muted">
                最近运行：{task.last_run?.status ? translateStatus(task.last_run.status) : '尚未开始'}
              </div>
            </button>
          ))}
          {!basRuns.length && <p className="muted">暂无 BAS 任务，选择场景后点击“运行”即可发起。</p>}
        </div>
      </section>

      <section className="card bas-run-detail">
        <header className="section-header">
          <div>
            <h2>执行时间线 & 攻击链</h2>
            <p className="muted">
              展示单次 BAS 演练的步骤进度、失败节点及沙箱使用情况，辅助溯源与调试。
            </p>
          </div>
        </header>
        {selectedRunId && runReport && (
          <BASRunInsight report={runReport} loading={isReportLoading} />
        )}
        {selectedRunId && !runReport && isReportLoading && <p className="muted">载入执行详情…</p>}
        {!selectedRunId && <p className="muted">请选择左侧执行队列中的任务查看详情。</p>}
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

function statusClass(status: string) {
  const normalized = status?.toLowerCase?.() ?? 'unknown';
  if (normalized.includes('fail') || normalized.includes('error')) return 'failed';
  if (normalized.includes('cancel')) return 'canceled';
  if (normalized.includes('pending') || normalized.includes('lease') || normalized.includes('run')) return 'running';
  if (normalized.includes('queued')) return 'queued';
  return 'succeeded';
}

function translateStatus(status: string) {
  const map: Record<string, string> = {
    pending: '等待调度',
    leased: '已分配',
    running: '执行中',
    succeeded: '成功',
    failed: '失败',
    canceled: '已取消',
    active: '启用',
    approved: '已审批',
  };
  return map[status.toLowerCase()] ?? status;
}

function BASRunInsight({ report, loading }: { report: BASRunReport; loading: boolean }) {
  const startedAt = report.run_metadata?.started_at;
  const durationText =
    report.completed_at && startedAt
      ? `${new Date(startedAt).toLocaleTimeString()} → ${new Date(report.completed_at).toLocaleTimeString()}`
      : report.completed_at
        ? new Date(report.completed_at).toLocaleString()
        : '进行中';
  return (
    <div className="run-detail">
      <div className="run-header">
        <div>
          <h3>{report.scenario_name ?? report.scenario_id ?? '未命名场景'}</h3>
          <p className="muted">
            #{report.task_id.slice(-6)} · 状态 {translateStatus(report.task_status)} · {durationText}
          </p>
        </div>
        {loading && <span className="muted">同步中…</span>}
      </div>
      <div className="bas-summary-grid">
        <SummaryCard label="成功" value={report.summary.success} tone="success" />
        <SummaryCard label="失败" value={report.summary.failed} tone="danger" />
        <SummaryCard label="已跳过" value={report.summary.skipped} />
        <SummaryCard label="总步骤" value={report.summary.total} />
      </div>
      <RunTimeline steps={report.steps} />
      <AttackPathPreview steps={report.steps} />
      <div className="metadata-grid">
        <div>
          <h4>沙箱使用</h4>
          <p className="muted">
            {report.run_metadata?.sandbox_executed === 'true' ? '已启用' : '未启用'} ·{' '}
            {report.run_metadata?.sandbox_fallback === 'true' ? '发生回退' : '无回退'}
          </p>
        </div>
        <div>
          <h4>标签</h4>
          <p className="muted">{report.scenario_tags?.join(', ') || '—'}</p>
        </div>
        <div>
          <h4>失败步骤</h4>
          <p className="muted">{report.failed_steps?.join(', ') || '暂无'}</p>
        </div>
      </div>
    </div>
  );
}

function RunTimeline({ steps }: { steps?: BASRunReport['steps'] }) {
  if (!steps?.length) {
    return <p className="muted">暂无步骤信息，等待 Agent 上报。</p>;
  }

  return (
    <ol className="run-timeline">
      {steps.map((step) => {
        const cls = statusClass(step.status);
        const started = step.started_at ? new Date(step.started_at).toLocaleTimeString() : '—';
        const ended = step.ended_at ? new Date(step.ended_at).toLocaleTimeString() : '—';
        return (
          <li key={step.id} className={`run-step status-${cls}`}>
            <div>
              <strong>{step.name}</strong>
              <span className="muted"> · {translateStatus(step.status)}</span>
            </div>
            <div className="muted">
              {started} → {ended} · {step.sandbox ? 'Sandbox' : '原地'}
            </div>
            {step.message && <div className="run-step-message">{step.message}</div>}
          </li>
        );
      })}
    </ol>
  );
}

function AttackPathPreview({ steps }: { steps?: BASRunReport['steps'] }) {
  if (!steps?.length) {
    return null;
  }
  return (
    <div className="attack-path" aria-label="attack-path-preview">
      {steps.map((step, index) => (
        <div key={step.id} className="attack-segment">
          <div className={`attack-node status-${statusClass(step.status)}`}>
            <strong>{step.name}</strong>
            <span>{translateStatus(step.status)}</span>
          </div>
          {index < steps.length - 1 && <div className="attack-connector" />}
        </div>
      ))}
    </div>
  );
}

function SummaryCard({ label, value, tone }: { label: string; value: number; tone?: 'success' | 'danger' }) {
  return (
    <article className={`summary-card ${tone ? `tone-${tone}` : ''}`}>
      <span>{label}</span>
      <strong>{value}</strong>
    </article>
  );
}
