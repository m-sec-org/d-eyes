import type { Task } from '@/services/types';
import dayjs from 'dayjs';
import { useMemo } from 'react';
import useSWR from 'swr';
import { Drawer, Descriptions, Tag, List, Space, Button } from 'antd';

import { fetchTaskVisuals } from '@/services/api/taskVisuals';
import { TaskVisualTabs } from './TaskVisualTabs';

interface TaskDetailDrawerProps {
  task: Task | null;
  onClose: () => void;
}

export function TaskDetailDrawer({ task, onClose }: TaskDetailDrawerProps) {
  const executionSummary = useMemo(() => {
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
  }, [task]);

  const { data: visuals } = useSWR(task ? ['task-visuals', task.id] : null, () => fetchTaskVisuals(task!.id));

  return (
    <Drawer
      title="任务详情"
      placement="right"
      width={480}
      onClose={onClose}
      open={!!task}
      destroyOnClose
      aria-label="任务详情抽屉"
    >
      {task && (
        <Space direction="vertical" style={{ width: '100%' }} size="large">
          <Descriptions column={1} size="small" bordered>
            <Descriptions.Item label="任务类型">{task.type}</Descriptions.Item>
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

          {executionSummary && (
            <Descriptions column={1} size="small" title="执行摘要" bordered>
              <Descriptions.Item label="命令">{executionSummary.command ?? '—'}</Descriptions.Item>
              <Descriptions.Item label="持续时间">
                {executionSummary.duration ? `${executionSummary.duration}s` : '—'}
              </Descriptions.Item>
              <Descriptions.Item label="风险摘要">
                {executionSummary.risks
                  ? Object.entries(executionSummary.risks)
                      .map(([level, count]) => `${level}: ${count}`)
                      .join(' / ')
                  : '—'}
              </Descriptions.Item>
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

          {executionSummary?.outputs && executionSummary.outputs.length > 0 && (
            <List
              size="small"
              header="产出 / 附件"
              bordered
              dataSource={executionSummary.outputs}
              renderItem={(output) => (
                <List.Item actions={[<Button type="link" key="download">下载</Button>]}>
                  {output.label ?? output.path.split('/').pop()}
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
