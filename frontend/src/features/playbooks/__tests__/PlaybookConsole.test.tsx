import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { SWRConfig } from 'swr';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { PlaybookConsole } from '@/features/playbooks/PlaybookConsole';
import type { Playbook } from '@/services/types';

const mockPlaybook: Playbook = {
  id: 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
  name: '恶意样本隔离',
  description: '当检测到高危样本时隔离主机',
  status: 'draft',
  trigger: {
    type: 'behavior.anomaly',
    filter: { severity: 'high' },
  },
  conditions: ['agent.labels.env == "prod"'],
  approvals: [{ role: 'security.lead', timeout: 1800 }],
  actions: [{ type: 'notify', target: 'slack://sec-ops' }],
  rollback: [{ type: 'notify', target: 'slack://sec-ops-rollback' }],
  created_by: 'system',
  updated_by: 'system',
  approved_by: null,
  created_at: new Date().toISOString(),
  updated_at: new Date().toISOString(),
  last_run_at: null,
  version: 1,
};

const mockServices = {
  listPlaybooks: vi.fn(async () => [mockPlaybook]),
  listPlaybookRuns: vi.fn(async () => []),
  createPlaybook: vi.fn(),
  activatePlaybook: vi.fn(),
  runPlaybook: vi.fn(),
};

vi.mock('@/services/api/playbooks', () => mockServices);

if (!global.ResizeObserver) {
  global.ResizeObserver = class {
    observe() {}
    unobserve() {}
    disconnect() {}
  };
}

const renderConsole = () =>
  render(
    <SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0, shouldRetryOnError: false }}>
      <PlaybookConsole />
    </SWRConfig>
  );

describe('PlaybookConsole form validation', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('prevents creating playbook when trigger JSON is invalid', async () => {
    const user = userEvent.setup();
    renderConsole();
    const triggerField = await screen.findByLabelText('触发器 JSON');
    await user.clear(triggerField);
    await user.type(triggerField, '{"type": invalid');
    await user.click(screen.getByRole('button', { name: '创建 Playbook' }));
    expect(await screen.findByText('触发器 JSON 必须是合法 JSON')).toBeInTheDocument();
    expect(mockServices.createPlaybook).not.toHaveBeenCalled();
  });

  it('blocks manual run when payload JSON is malformed', async () => {
    const user = userEvent.setup();
    renderConsole();
    const payloadField = await screen.findByLabelText('Payload JSON');
    await user.type(payloadField, '{bad');
    await user.click(screen.getByRole('button', { name: '触发 Playbook' }));
    expect(await screen.findByText('Payload JSON 必须是合法 JSON')).toBeInTheDocument();
    expect(mockServices.runPlaybook).not.toHaveBeenCalled();
  });
});
