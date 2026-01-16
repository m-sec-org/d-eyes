import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { SWRConfig } from 'swr';

import { TaskDetailDrawer } from '../TaskDetailDrawer';
import type { Task } from '@/services/types';
import { getTaskDetectReport } from '@/services/api/taskReports';
import { fetchTaskVisuals } from '@/services/api/taskVisuals';

vi.mock('@/services/api/taskReports', () => ({
  getTaskAuditReport: vi.fn(),
  getTaskDetectReport: vi.fn(),
}));

vi.mock('@/services/api/taskVisuals', () => ({
  fetchTaskVisuals: vi.fn(),
}));

const renderDrawer = (task: Task) =>
  render(
    <SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0, revalidateOnFocus: false }}>
      <TaskDetailDrawer task={task} onClose={vi.fn()} />
    </SWRConfig>
  );

describe('TaskDetailDrawer', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    (fetchTaskVisuals as unknown as vi.Mock).mockResolvedValue([]);
  });

  it('renders expandable debug metadata panel', async () => {
    (getTaskDetectReport as unknown as vi.Mock).mockResolvedValue({
      task_id: '00000000-0000-0000-0000-000000000301',
      task_type: 'detect.diag',
      profile: 'default',
      run_id: '00000000-0000-0000-0000-000000000302',
      agent_id: '00000000-0000-0000-0000-000000000303',
      task_status: 'succeeded',
      result: {
        status: 'succeeded',
        summary: {
          command: 'diag',
          status: 'succeeded',
          duration_seconds: 1,
        },
        metadata: { foo: 'bar' },
      },
      run_metadata: { run: 'meta' },
      exit_code: 0,
      completed_at: '2025-01-01T00:00:00.000Z',
    });

    const user = userEvent.setup();
    renderDrawer({
      id: '00000000-0000-0000-0000-000000000301',
      type: 'detect.diag',
      profile: 'default',
      priority: 3,
      status: 'succeeded',
      retry_count: 0,
      created_at: '2025-01-01T00:00:00.000Z',
      updated_at: '2025-01-01T00:00:00.000Z',
      last_run: null,
    });

    const toggle = await screen.findByText('调试信息（JSON）');
    await user.click(toggle);

    expect(screen.getByText('result.metadata')).toBeInTheDocument();
    expect(screen.getAllByText(/"foo": "bar"/).length).toBeGreaterThan(0);
    expect(screen.getByText('run_metadata')).toBeInTheDocument();
    expect(screen.getByText(/"run": "meta"/)).toBeInTheDocument();
    expect(screen.getByText('result.summary')).toBeInTheDocument();
    expect(screen.getAllByText(/"duration_seconds": 1/).length).toBeGreaterThan(0);
    expect(screen.getByText('result')).toBeInTheDocument();
  });

  it('renders risks and notes from report summary', async () => {
    (getTaskDetectReport as unknown as vi.Mock).mockResolvedValue({
      task_id: '00000000-0000-0000-0000-000000000101',
      task_type: 'detect.diag',
      profile: 'default',
      run_id: '00000000-0000-0000-0000-000000000102',
      agent_id: '00000000-0000-0000-0000-000000000103',
      task_status: 'succeeded',
      result: {
        status: 'succeeded',
        summary: {
          command: 'diag',
          status: 'succeeded',
          duration_seconds: 1.23,
          risks: { high: 1, medium: 2 },
          notes: ['note-a', 'note-b'],
        },
      },
      exit_code: 0,
      completed_at: '2025-01-01T00:00:00.000Z',
    });

    renderDrawer({
      id: '00000000-0000-0000-0000-000000000101',
      type: 'detect.diag',
      profile: 'default',
      priority: 3,
      status: 'succeeded',
      retry_count: 0,
      created_at: '2025-01-01T00:00:00.000Z',
      updated_at: '2025-01-01T00:00:00.000Z',
      last_run: null,
    });

    expect(await screen.findByText('高危: 1')).toBeInTheDocument();
    expect(screen.getByText('中危: 2')).toBeInTheDocument();
    expect(screen.getByText(/note-a/)).toBeInTheDocument();
    expect(screen.getByText(/note-b/)).toBeInTheDocument();
  });

  it('shows actionable guidance for detect.memscan.approval_required', async () => {
    (getTaskDetectReport as unknown as vi.Mock).mockResolvedValue({
      task_id: '00000000-0000-0000-0000-000000000001',
      task_type: 'detect.memscan',
      profile: 'default',
      run_id: '00000000-0000-0000-0000-000000000002',
      agent_id: '00000000-0000-0000-0000-000000000003',
      task_status: 'failed',
      result: {
        status: 'failed',
        summary: {
          command: 'memscan',
          status: 'failed',
          duration_seconds: 0.5,
        },
        error: 'approval required',
        error_code: 'detect.memscan.approval_required',
      },
      exit_code: 65,
      error_code: 'detect.memscan.approval_required',
      completed_at: '2025-01-01T00:00:00.000Z',
    });

    renderDrawer({
      id: '00000000-0000-0000-0000-000000000001',
      type: 'detect.memscan',
      profile: 'default',
      priority: 3,
      status: 'failed',
      retry_count: 0,
      created_at: '2025-01-01T00:00:00.000Z',
      updated_at: '2025-01-01T00:00:00.000Z',
      last_run: null,
    });

    expect(await screen.findByText('Memscan 审批缺失')).toBeInTheDocument();
    expect(screen.getByText('detect.memscan.approval_required')).toBeInTheDocument();
    expect(screen.getByText(/memscan_approval_required="true"/)).toBeInTheDocument();
    expect(screen.getByText(/memscan_approved="true"/)).toBeInTheDocument();
  });

  it('shows guidance for agent.remote_execution_failed', async () => {
    (getTaskDetectReport as unknown as vi.Mock).mockResolvedValue({
      task_id: '00000000-0000-0000-0000-000000000201',
      task_type: 'detect.diag',
      profile: 'default',
      run_id: '00000000-0000-0000-0000-000000000202',
      agent_id: '00000000-0000-0000-0000-000000000203',
      task_status: 'failed',
      result: {
        status: 'failed',
        summary: {
          command: 'diag',
          status: 'failed',
          duration_seconds: 0.1,
          error_message: 'unsupported task type',
        },
        error: 'unsupported task type',
        error_code: 'agent.remote_execution_failed',
      },
      exit_code: 1,
      error_code: 'agent.remote_execution_failed',
      completed_at: '2025-01-01T00:00:00.000Z',
    });

    renderDrawer({
      id: '00000000-0000-0000-0000-000000000201',
      type: 'detect.diag',
      profile: 'default',
      priority: 3,
      status: 'failed',
      retry_count: 0,
      created_at: '2025-01-01T00:00:00.000Z',
      updated_at: '2025-01-01T00:00:00.000Z',
      last_run: null,
    });

    expect(await screen.findByText('Agent 远程执行失败')).toBeInTheDocument();
    expect(screen.getByText('agent.remote_execution_failed')).toBeInTheDocument();
    expect(screen.getByText(/确认 task type/i)).toBeInTheDocument();
  });

  it('shows friendly empty state when report is not ready (404)', async () => {
    (getTaskDetectReport as unknown as vi.Mock).mockRejectedValue({ response: { status: 404 }, message: 'not found' });

    renderDrawer({
      id: '00000000-0000-0000-0000-000000000011',
      type: 'detect.memscan',
      profile: 'default',
      priority: 3,
      status: 'running',
      retry_count: 0,
      created_at: '2025-01-01T00:00:00.000Z',
      updated_at: '2025-01-01T00:00:00.000Z',
      last_run: null,
    });

    expect(await screen.findByText('报告尚未产出')).toBeInTheDocument();
  });
});
