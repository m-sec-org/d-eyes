import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { SWRConfig } from 'swr';

import { AgentDirectory } from '../AgentDirectory';
import { listAgents, updateAgentLabels } from '@/services/api/agents';

vi.mock('@/services/api/agents', () => ({
  listAgents: vi.fn(),
  updateAgentLabels: vi.fn(),
}));

const renderDirectory = () =>
  render(
    <SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0, revalidateOnFocus: false }}>
      <AgentDirectory />
    </SWRConfig>
  );

describe('AgentDirectory', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    (updateAgentLabels as unknown as vi.Mock).mockResolvedValue(undefined);
  });

  it('shows reserved labels as read-only and excludes them from the editor textarea', async () => {
    (listAgents as unknown as vi.Mock).mockResolvedValue([
      {
        id: 'agent-1',
        name: 'agent-one',
        status: 'online',
        platform: 'windows',
        version: '1.0.0',
        capabilities: ['detect.memscan'],
        labels: { allow_memscan: 'true', mode: 'prod', 'build.commit': 'abc', foo: 'bar' },
        last_heartbeat: null,
      },
    ]);

    const user = userEvent.setup();
    renderDirectory();

    await user.click(await screen.findByRole('button', { name: '标签' }));

    expect(screen.getByText('提示：Server-side 标签编辑是非权威的')).toBeInTheDocument();
    expect(screen.getByText('保留键（Agent 管理，只读）')).toBeInTheDocument();
    expect(screen.getByText('allow_memscan:true')).toBeInTheDocument();
    expect(screen.getByText('mode:prod')).toBeInTheDocument();
    expect(screen.getByText('build.commit:abc')).toBeInTheDocument();

    const textarea = screen.getByRole('textbox', { name: 'Agent 标签输入（key:value）' });
    expect(textarea).toBeInTheDocument();
    expect(textarea).toHaveValue('foo:bar');
    expect(textarea).not.toHaveValue(expect.stringContaining('allow_memscan'));
    expect(textarea).not.toHaveValue(expect.stringContaining('build.'));
    expect(textarea).not.toHaveValue(expect.stringContaining('mode'));
  });

  it('preserves reserved labels and ignores attempts to edit them', async () => {
    (listAgents as unknown as vi.Mock).mockResolvedValue([
      {
        id: 'agent-1',
        name: 'agent-one',
        status: 'online',
        platform: 'windows',
        version: '1.0.0',
        capabilities: ['detect.memscan'],
        labels: { allow_memscan: 'true', mode: 'prod', 'build.commit': 'abc', foo: 'bar' },
        last_heartbeat: null,
      },
    ]);

    const user = userEvent.setup();
    renderDirectory();

    await user.click(await screen.findByRole('button', { name: '标签' }));

    const textarea = screen.getByRole('textbox', { name: 'Agent 标签输入（key:value）' });
    await user.clear(textarea);
    await user.type(textarea, 'foo:baz\nallow_memscan:false');

    await user.click(screen.getByRole('button', { name: '保存' }));

    await waitFor(() =>
      expect(updateAgentLabels).toHaveBeenCalledWith('agent-1', {
        foo: 'baz',
        allow_memscan: 'true',
        mode: 'prod',
        'build.commit': 'abc',
      })
    );
  });
});
