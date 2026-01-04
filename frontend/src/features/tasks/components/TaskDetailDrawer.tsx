import type { Task } from '@/services/types';
import dayjs from 'dayjs';
import { useMemo } from 'react';
import useSWR from 'swr';
import { Alert, Button, Collapse, Descriptions, Divider, Drawer, List, Space, Spin, Tag, Typography } from 'antd';

import { fetchTaskVisuals } from '@/services/api/taskVisuals';
import { getTaskAuditReport, getTaskDetectReport } from '@/services/api/taskReports';
import { TaskVisualTabs } from './TaskVisualTabs';
import { CodeBlock } from '@/components/CodeBlock';

interface TaskDetailDrawerProps {
  task: Task | null;
  onClose: () => void;
}

function resolveReportKind(taskType: string): 'audit' | 'detect' | null {
  const normalized = taskType.toLowerCase();
  if (normalized === 'audit' || normalized.startsWith('audit.')) return 'audit';
  if (normalized === 'detect' || normalized.startsWith('detect.')) return 'detect';
  return null;
}

function getHttpStatus(error: unknown): number | undefined {
  const status = (error as any)?.response?.status;
  return typeof status === 'number' ? status : undefined;
}

function buildErrorGuidance(errorCode: string) {
  switch (errorCode) {
    case 'detect.memscan.approval_required':
      return {
        title: 'Memscan 审批缺失',
        description: (
          <div>
            <div>建议动作：</div>
            <ul style={{ margin: '0.25rem 0 0', paddingLeft: '1.25rem' }}>
              <li>
                创建任务时补齐 metadata：
                <code> memscan_approval_required="true"</code>、<code>memscan_approved="true"</code>
              </li>
              <li>
                确认 Agent 为 Windows 且已 opt-in：<code>allow_memscan="true"</code>
              </li>
            </ul>
          </div>
        ),
      };
    case 'detect.memscan.evidence_approval_required':
      return {
        title: 'Evidence/Minidump 审批缺失',
        description: (
          <div>
            <div>建议动作：</div>
            <ul style={{ margin: '0.25rem 0 0', paddingLeft: '1.25rem' }}>
              <li>
                若启用 <code>payload.evidence</code> 或 <code>payload.minidump</code>，需额外补齐 metadata：
                <code> memscan_evidence_approved="true"</code>
              </li>
              <li>或关闭 evidence/minidump 后重新创建任务</li>
            </ul>
          </div>
        ),
      };
    case 'agent.remote_execution_failed':
      return {
        title: 'Agent 远程执行失败',
        description: (
          <div>
            <div>建议动作：</div>
            <ul style={{ margin: '0.25rem 0 0', paddingLeft: '1.25rem' }}>
              <li>确认 Agent 与 Server 之间连接正常，并尝试重试任务</li>
              <li>确认 task type / profile / payload 合法（不支持或校验失败会走 reportFailure）</li>
              <li>查看 Agent 日志以定位失败点（常见：任务类型不存在、payload 校验不通过）</li>
            </ul>
          </div>
        ),
      };
    case 'bas.step_failed':
      return {
        title: 'BAS 步骤失败',
        description: (
          <div>
            <div>建议动作：</div>
            <ul style={{ margin: '0.25rem 0 0', paddingLeft: '1.25rem' }}>
              <li>查看 BAS 场景报告/产出路径与失败步骤信息（failed_steps）</li>
              <li>根据失败步骤的 stdout/stderr 与运行环境（sandbox/权限）排查后重试</li>
            </ul>
          </div>
        ),
      };
    default:
      break;
  }

  if (errorCode.startsWith('agent.')) {
    return {
      title: 'Agent 执行失败',
      description: (
        <div>
          <div>建议动作：</div>
          <ul style={{ margin: '0.25rem 0 0', paddingLeft: '1.25rem' }}>
            <li>检查 Agent 是否在线、网络是否通畅，并重试任务</li>
            <li>确认 task type / profile / payload 符合 Agent 支持范围（不支持或校验失败会直接失败）</li>
            <li>查看 Agent 端日志定位具体失败原因（常见：任务类型不存在、payload 校验不通过）</li>
          </ul>
        </div>
      ),
    };
  }

  if (errorCode.startsWith('bas.')) {
    return {
      title: 'BAS 执行失败',
      description: (
        <div>
          <div>建议动作：</div>
          <ul style={{ margin: '0.25rem 0 0', paddingLeft: '1.25rem' }}>
            <li>查看 BAS 场景报告与失败步骤信息（failed_steps）</li>
            <li>若启用了 Sandbox/审批策略，确认审批输入与运行环境符合要求</li>
          </ul>
        </div>
      ),
    };
  }

  return null;
}

function renderRisks(risks?: Record<string, number>) {
  if (!risks || Object.keys(risks).length === 0) return '—';

  const entries = Object.entries(risks).filter(([, count]) => typeof count === 'number' && count > 0);
  if (entries.length === 0) return '—';

  const order = ['critical', 'high', 'medium', 'low', 'info'];
  const labelMap: Record<string, string> = {
    critical: '严重',
    high: '高危',
    medium: '中危',
    low: '低危',
    info: '信息',
  };
  const colorMap: Record<string, string> = {
    critical: 'magenta',
    high: 'red',
    medium: 'orange',
    low: 'green',
    info: 'blue',
  };

  const sorted = [...entries].sort(([a], [b]) => {
    const ai = order.indexOf(a);
    const bi = order.indexOf(b);
    if (ai === -1 && bi === -1) return a.localeCompare(b);
    if (ai === -1) return 1;
    if (bi === -1) return -1;
    return ai - bi;
  });

  return (
    <Space size={[4, 4]} wrap>
      {sorted.map(([level, count]) => (
        <Tag key={level} color={colorMap[level] ?? 'default'}>
          {labelMap[level] ?? level}: {count}
        </Tag>
      ))}
    </Space>
  );
}

export function TaskDetailDrawer({ task, onClose }: TaskDetailDrawerProps) {
  const reportKind = task ? resolveReportKind(task.type) : null;
  const {
    data: report,
    error: reportError,
    isLoading: reportLoading,
    mutate: refreshReport,
  } = useSWR(
    task && reportKind ? ['task-report', reportKind, task.id] : null,
    () => (reportKind === 'audit' ? getTaskAuditReport(task!.id) : getTaskDetectReport(task!.id))
  );

  const executionSummary = useMemo(() => {
    if (report?.result?.summary) {
      const summary = report.result.summary;
      return {
        command: summary.command,
        status: summary.status,
        duration: summary.duration_seconds,
        risks: summary.risks,
        notes: summary.notes,
        outputs: summary.outputs,
      };
    }

    if (!task?.last_run?.summary || typeof task.last_run.summary !== 'object') return null;
    const rawSummary = task.last_run.summary as Record<string, unknown>;
    const nested =
      typeof rawSummary.summary === 'object' && rawSummary.summary !== null
        ? (rawSummary.summary as Record<string, unknown>)
        : rawSummary;

    const getString = (value: unknown) => (typeof value === 'string' ? value : undefined);

    return {
      command: getString(nested.command),
      status: getString(nested.status),
      duration: typeof nested.duration_seconds === 'number' ? nested.duration_seconds : undefined,
      risks: typeof nested.risks === 'object' ? (nested.risks as Record<string, number>) : undefined,
      notes: Array.isArray(nested.notes) ? (nested.notes as string[]) : undefined,
      outputs: Array.isArray(nested.outputs)
        ? (nested.outputs as { path: string; label?: string; type?: string }[])
        : undefined,
    };
  }, [report, task]);

  const exitCode = report?.exit_code ?? report?.result.exit_code ?? task?.last_run?.exit_code;
  const errorCode = report?.error_code ?? report?.result.error_code ?? task?.last_run?.error_code;
  const errorMessage = report?.result.error ?? report?.result.summary.error_message;
  const errorGuidance = errorCode ? buildErrorGuidance(errorCode) : null;

  const { data: visuals } = useSWR(task ? ['task-visuals', task.id] : null, () => fetchTaskVisuals(task!.id));

  return (
    <Drawer
      title="任务详情"
      placement="right"
      width={480}
      onClose={onClose}
      open={!!task}
      destroyOnHidden
      aria-label="任务详情抽屉"
    >
      {task && (
        <Space direction="vertical" style={{ width: '100%' }} size="large">
          <Descriptions column={1} size="small" bordered>
            <Descriptions.Item label="任务类型">{task.type}</Descriptions.Item>
            <Descriptions.Item label="Profile">{task.profile ?? '—'}</Descriptions.Item>
            <Descriptions.Item label="状态">
              <Tag color={statusColor(task.status)}>{task.status}</Tag>
            </Descriptions.Item>
            <Descriptions.Item label="优先级">P{task.priority}</Descriptions.Item>
            <Descriptions.Item label="创建人">{task.created_by ?? 'unknown'}</Descriptions.Item>
            <Descriptions.Item label="创建时间">{dayjs(task.created_at).format('YYYY-MM-DD HH:mm')}</Descriptions.Item>
            <Descriptions.Item label="最近更新">{dayjs(task.updated_at).format('YYYY-MM-DD HH:mm')}</Descriptions.Item>
          </Descriptions>

          <Descriptions column={1} size="small" title="上下文">
            <Descriptions.Item label="目标/场景">
              {task.metadata?.targets ?? task.metadata?.scenario_id ?? '—'}
            </Descriptions.Item>
          </Descriptions>

          {(exitCode !== undefined || errorCode || errorMessage) && (
            <Space direction="vertical" style={{ width: '100%' }} size="small">
              <Descriptions column={1} size="small" title="执行结果" bordered>
                <Descriptions.Item label="Exit Code">{exitCode ?? '—'}</Descriptions.Item>
                <Descriptions.Item label="Error Code">{errorCode ? <Tag color="red">{errorCode}</Tag> : '—'}</Descriptions.Item>
                <Descriptions.Item label="错误信息">{errorMessage ?? '—'}</Descriptions.Item>
              </Descriptions>
              {errorGuidance && (
                <Alert type="warning" showIcon message={errorGuidance.title} description={errorGuidance.description} />
              )}
            </Space>
          )}

          {executionSummary && (
            <Descriptions column={1} size="small" title="执行摘要" bordered>
              <Descriptions.Item label="命令">{executionSummary.command ?? '—'}</Descriptions.Item>
              <Descriptions.Item label="状态">{executionSummary.status ?? '—'}</Descriptions.Item>
              <Descriptions.Item label="持续时间">
                {executionSummary.duration ? `${executionSummary.duration}s` : '—'}
              </Descriptions.Item>
              <Descriptions.Item label="风险摘要">{renderRisks(executionSummary.risks)}</Descriptions.Item>
            </Descriptions>
          )}

          {executionSummary?.notes && executionSummary.notes.length > 0 && (
            <List
              size="small"
              header="执行备注"
              bordered
              dataSource={executionSummary.notes}
              renderItem={(note) => <List.Item>• {note}</List.Item>}
            />
          )}

          {reportKind && (
            <>
              <Divider style={{ margin: '0.5rem 0' }} />
              <Space direction="vertical" style={{ width: '100%' }} size="small">
                <Space align="center" style={{ width: '100%', justifyContent: 'space-between' }}>
                  <Typography.Text strong>报告（{reportKind}）</Typography.Text>
                  <Button size="small" onClick={() => refreshReport()}>
                    刷新
                  </Button>
                </Space>
                {reportLoading && (
                  <div style={{ display: 'flex', justifyContent: 'center', padding: '0.5rem 0' }}>
                    <Spin />
                  </div>
                )}
                {!reportLoading && reportError && (
                  <>
                    {getHttpStatus(reportError) === 403 ? (
                      <Alert type="error" showIcon message="无权限查看报告（需要 reports.view）" />
                    ) : getHttpStatus(reportError) === 404 ? (
                      <Alert
                        type="info"
                        showIcon
                        message="报告尚未产出"
                        description="任务可能仍在运行/等待产出报告，可稍后重试；也可先参考上方 last_run 的摘要信息。"
                      />
                    ) : (
                      <Alert type="error" showIcon message="拉取报告失败" description={String((reportError as any)?.message ?? reportError)} />
                    )}
                  </>
                )}
                {report && (
                  <>
                    <Descriptions column={1} size="small" bordered>
                      <Descriptions.Item label="Task ID">
                        <Typography.Text code copyable>
                          {report.task_id}
                        </Typography.Text>
                      </Descriptions.Item>
                      <Descriptions.Item label="Run ID">
                        <Typography.Text code copyable>
                          {report.run_id}
                        </Typography.Text>
                      </Descriptions.Item>
                      <Descriptions.Item label="Agent ID">
                        <Typography.Text code copyable>
                          {report.agent_id}
                        </Typography.Text>
                      </Descriptions.Item>
                      <Descriptions.Item label="任务状态">{report.task_status}</Descriptions.Item>
                      <Descriptions.Item label="完成时间">
                        {report.completed_at ? dayjs(report.completed_at).format('YYYY-MM-DD HH:mm') : '—'}
                      </Descriptions.Item>
                    </Descriptions>

                    {(report.result.summary.outputs?.length ?? 0) > 0 && (
                      <List
                        size="small"
                        header="Outputs（Agent 本地路径，仅支持复制）"
                        bordered
                        dataSource={report.result.summary.outputs}
                        renderItem={(output) => (
                          <List.Item>
                            <Space direction="vertical" size={0}>
                              <span>{output.label ?? output.path.split(/[\\/]/).pop()}</span>
                              <Typography.Text code copyable={{ text: output.path }} style={{ color: 'rgba(0,0,0,0.65)' }}>
                                {output.path}
                              </Typography.Text>
                            </Space>
                          </List.Item>
                        )}
                      />
                    )}

                    {(report.result.artifacts?.length ?? 0) > 0 && (
                      <List
                        size="small"
                        header="Artifacts（Agent 本地路径，仅支持复制）"
                        bordered
                        dataSource={report.result.artifacts}
                        renderItem={(artifact) => (
                          <List.Item>
                            <Space direction="vertical" size={0}>
                              <span>{artifact.label ?? artifact.path.split(/[\\/]/).pop()}</span>
                              <Typography.Text code copyable={{ text: artifact.path }} style={{ color: 'rgba(0,0,0,0.65)' }}>
                                {artifact.path}
                              </Typography.Text>
                            </Space>
                          </List.Item>
                        )}
                      />
                    )}

                    <Collapse
                      ghost
                      items={[
                        {
                          key: 'debug',
                          label: '调试信息（JSON）',
                          children: (
                            <Space direction="vertical" size="small" style={{ width: '100%' }}>
                              {Object.keys(report.result.metadata ?? {}).length > 0 && (
                                <CodeBlock title="result.metadata" value={report.result.metadata} maxHeight={240} />
                              )}
                              {Object.keys(report.run_metadata ?? {}).length > 0 && (
                                <CodeBlock title="run_metadata" value={report.run_metadata} maxHeight={240} />
                              )}
                              <CodeBlock title="result.summary" value={report.result.summary} maxHeight={240} />
                              <CodeBlock title="result" value={report.result} maxHeight={240} />
                            </Space>
                          ),
                        },
                      ]}
                    />
                  </>
                )}
              </Space>
            </>
          )}

          {!report && executionSummary?.outputs && executionSummary.outputs.length > 0 && (
            <List
              size="small"
              header="产出 / 附件（来自 last_run，路径仅支持复制）"
              bordered
              dataSource={executionSummary.outputs}
              renderItem={(output) => (
                <List.Item>
                  <Space direction="vertical" size={0}>
                    <span>{output.label ?? output.path.split(/[\\/]/).pop()}</span>
                    <Typography.Text code copyable={{ text: output.path }} style={{ color: 'rgba(0,0,0,0.65)' }}>
                      {output.path}
                    </Typography.Text>
                  </Space>
                </List.Item>
              )}
            />
          )}

          {visuals && visuals.length > 0 && <TaskVisualTabs visuals={visuals} />}

          <Space>
            <Button type="primary">重试任务</Button>
            <Button>暂停/取消</Button>
            <Button>基于此创建响应任务</Button>
          </Space>
        </Space>
      )}
    </Drawer>
  );
}

function statusColor(status: string) {
  switch (status) {
    case 'failed':
      return 'error';
    case 'running':
    case 'leased':
      return 'processing';
    case 'pending':
      return 'default';
    case 'succeeded':
      return 'success';
    default:
      return 'default';
  }
}
