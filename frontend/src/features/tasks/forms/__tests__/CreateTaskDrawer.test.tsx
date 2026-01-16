import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { SWRConfig } from 'swr';

import { CreateTaskDrawer } from '../CreateTaskDrawer';
import { createTask } from '@/services/api/taskActions';
import { listTaskProfiles, listTaskTypes } from '@/services/api/taskCatalog';

vi.mock('@/services/api/taskCatalog', () => ({
  listTaskTypes: vi.fn(),
  listTaskProfiles: vi.fn(),
}));

vi.mock('@/services/api/taskActions', () => ({
  createTask: vi.fn(),
}));

const renderDrawer = () =>
  render(
    <SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0, revalidateOnFocus: false }}>
      <CreateTaskDrawer open onClose={vi.fn()} onCreated={vi.fn()} />
    </SWRConfig>
  );

describe('CreateTaskDrawer', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    (createTask as unknown as vi.Mock).mockResolvedValue({ id: 'task-1' });
  });

  it('injects required_capabilities from task catalog capabilities', async () => {
    (listTaskTypes as unknown as vi.Mock).mockResolvedValue([
      { name: 'foo', display_name: 'Foo', capabilities: ['cap-a', 'cap-b'] },
    ]);
    (listTaskProfiles as unknown as vi.Mock).mockResolvedValue([
      {
        id: 'foo_profile_v1',
        task_type: 'foo',
        display_name: 'Foo Profile',
        version: '1.0.0',
        schema: { parameters: [] },
      },
    ]);

    const user = userEvent.setup();
    renderDrawer();

    const typeSelect = await screen.findByRole('combobox', { name: '任务类型' });
    await user.selectOptions(typeSelect, 'foo');

    const profileSelect = await screen.findByRole('combobox', { name: 'Profile' });
    await user.selectOptions(profileSelect, 'foo_profile_v1');

    const submitButton = screen.getByRole('button', { name: '创建' });
    await waitFor(() => expect(submitButton).toBeEnabled());
    await user.click(submitButton);

    await waitFor(() =>
      expect(createTask).toHaveBeenCalledWith(
        expect.objectContaining({
          type: 'foo',
          profile: 'foo_profile_v1',
          metadata: expect.objectContaining({
            required_capabilities: 'cap-a,cap-b',
          }),
        })
      )
    );
  });

  it('creates detect.memscan task with pid and approval metadata', async () => {
    (listTaskTypes as unknown as vi.Mock).mockResolvedValue([
      { name: 'detect.memscan', display_name: 'Detect Memscan', capabilities: ['detect.memscan'] },
    ]);
    (listTaskProfiles as unknown as vi.Mock).mockResolvedValue([
      {
        id: 'detect.memscan',
        task_type: 'detect.memscan',
        display_name: 'Detect Memscan Default',
        version: '1.0.0',
        schema: {
          parameters: [
            { key: 'pid', label: 'Process ID', type: 'number' },
            { key: 'all', label: 'Scan All Processes', type: 'boolean' },
            { key: 'evidence', label: 'Evidence', type: 'boolean', default: false },
          ],
        },
      },
    ]);

    const user = userEvent.setup();
    renderDrawer();

    const typeSelect = await screen.findByRole('combobox', { name: '任务类型' });
    await user.selectOptions(typeSelect, 'detect.memscan');

    const profileSelect = await screen.findByRole('combobox', { name: 'Profile' });
    await user.selectOptions(profileSelect, 'detect.memscan');

    const pidInput = await screen.findByRole('spinbutton', { name: 'Process ID' });
    await user.type(pidInput, '123');

    const approvalField = screen.getByText('执行审批').closest('.ui-field');
    expect(approvalField).not.toBeNull();
    await user.click(within(approvalField as HTMLElement).getByRole('checkbox'));

    const submitButton = screen.getByRole('button', { name: '创建' });
    await waitFor(() => expect(submitButton).toBeEnabled());
    await user.click(submitButton);

    await waitFor(() =>
      expect(createTask).toHaveBeenCalledWith(
        expect.objectContaining({
          type: 'detect.memscan',
          profile: 'detect.memscan',
          payload: expect.objectContaining({
            pid: 123,
          }),
          metadata: expect.objectContaining({
            required_capabilities: 'detect.memscan',
            memscan_approval_required: 'true',
            memscan_approved: 'true',
          }),
        })
      )
    );
  });

  it('shows field-level validation errors for detect.memscan', async () => {
    (listTaskTypes as unknown as vi.Mock).mockResolvedValue([
      { name: 'detect.memscan', display_name: 'Detect Memscan', capabilities: ['detect.memscan'] },
    ]);
    (listTaskProfiles as unknown as vi.Mock).mockResolvedValue([
      {
        id: 'detect.memscan',
        task_type: 'detect.memscan',
        display_name: 'Detect Memscan Default',
        version: '1.0.0',
        schema: {
          parameters: [
            { key: 'pid', label: 'Process ID', type: 'number' },
            { key: 'all', label: 'Scan All Processes', type: 'boolean' },
          ],
        },
      },
    ]);

    const user = userEvent.setup();
    renderDrawer();

    const typeSelect = await screen.findByRole('combobox', { name: '任务类型' });
    await user.selectOptions(typeSelect, 'detect.memscan');

    const profileSelect = await screen.findByRole('combobox', { name: 'Profile' });
    await user.selectOptions(profileSelect, 'detect.memscan');

    const submitButton = screen.getByRole('button', { name: '创建' });
    await waitFor(() => expect(submitButton).toBeDisabled());
    expect(screen.getAllByText('请选择 all 或填写 pid').length).toBeGreaterThan(0);
    expect(screen.getByText('需要确认已获得 memscan 执行审批')).toBeInTheDocument();
  });

  it('requires evidence approval when evidence/minidump is enabled', async () => {
    (listTaskTypes as unknown as vi.Mock).mockResolvedValue([
      { name: 'detect.memscan', display_name: 'Detect Memscan', capabilities: ['detect.memscan'] },
    ]);
    (listTaskProfiles as unknown as vi.Mock).mockResolvedValue([
      {
        id: 'detect.memscan',
        task_type: 'detect.memscan',
        display_name: 'Detect Memscan Default',
        version: '1.0.0',
        schema: {
          parameters: [
            { key: 'pid', label: 'Process ID', type: 'number' },
            { key: 'evidence', label: 'Evidence', type: 'boolean', default: false },
          ],
        },
      },
    ]);

    const user = userEvent.setup();
    renderDrawer();

    const typeSelect = await screen.findByRole('combobox', { name: '任务类型' });
    await user.selectOptions(typeSelect, 'detect.memscan');

    const profileSelect = await screen.findByRole('combobox', { name: 'Profile' });
    await user.selectOptions(profileSelect, 'detect.memscan');

    const pidInput = await screen.findByRole('spinbutton', { name: 'Process ID' });
    await user.type(pidInput, '7');

    const evidenceField = screen.getByText('Evidence').closest('.ui-field');
    expect(evidenceField).not.toBeNull();
    await user.click(within(evidenceField as HTMLElement).getByRole('checkbox'));

    const approvalField = screen.getByText('执行审批').closest('.ui-field');
    expect(approvalField).not.toBeNull();
    await user.click(within(approvalField as HTMLElement).getByRole('checkbox'));

    const submitButton = screen.getByRole('button', { name: '创建' });
    await waitFor(() => expect(submitButton).toBeDisabled());

    const evidenceApprovalField = await screen.findByText('Evidence/Minidump 审批');
    const evidenceApprovalContainer = evidenceApprovalField.closest('.ui-field');
    expect(evidenceApprovalContainer).not.toBeNull();
    await user.click(within(evidenceApprovalContainer as HTMLElement).getByRole('checkbox'));

    await waitFor(() => expect(submitButton).toBeEnabled());
    await user.click(submitButton);

    await waitFor(() =>
      expect(createTask).toHaveBeenCalledWith(
        expect.objectContaining({
          metadata: expect.objectContaining({
            memscan_evidence_approved: 'true',
          }),
        })
      )
    );
  });

  it('requires evidence approval when minidump is enabled', async () => {
    (listTaskTypes as unknown as vi.Mock).mockResolvedValue([
      { name: 'detect.memscan', display_name: 'Detect Memscan', capabilities: ['detect.memscan'] },
    ]);
    (listTaskProfiles as unknown as vi.Mock).mockResolvedValue([
      {
        id: 'detect.memscan',
        task_type: 'detect.memscan',
        display_name: 'Detect Memscan Default',
        version: '1.0.0',
        schema: {
          parameters: [
            { key: 'pid', label: 'Process ID', type: 'number' },
            { key: 'minidump', label: 'Minidump', type: 'boolean', default: false },
          ],
        },
      },
    ]);

    const user = userEvent.setup();
    renderDrawer();

    const typeSelect = await screen.findByRole('combobox', { name: '任务类型' });
    await user.selectOptions(typeSelect, 'detect.memscan');

    const profileSelect = await screen.findByRole('combobox', { name: 'Profile' });
    await user.selectOptions(profileSelect, 'detect.memscan');

    const pidInput = await screen.findByRole('spinbutton', { name: 'Process ID' });
    await user.type(pidInput, '7');

    const minidumpField = screen.getByText('Minidump').closest('.ui-field');
    expect(minidumpField).not.toBeNull();
    await user.click(within(minidumpField as HTMLElement).getByRole('checkbox'));

    const approvalField = screen.getByText('执行审批').closest('.ui-field');
    expect(approvalField).not.toBeNull();
    await user.click(within(approvalField as HTMLElement).getByRole('checkbox'));

    const submitButton = screen.getByRole('button', { name: '创建' });
    await waitFor(() => expect(submitButton).toBeDisabled());

    const evidenceApprovalField = await screen.findByText('Evidence/Minidump 审批');
    const evidenceApprovalContainer = evidenceApprovalField.closest('.ui-field');
    expect(evidenceApprovalContainer).not.toBeNull();
    await user.click(within(evidenceApprovalContainer as HTMLElement).getByRole('checkbox'));

    await waitFor(() => expect(submitButton).toBeEnabled());
    await user.click(submitButton);

    await waitFor(() =>
      expect(createTask).toHaveBeenCalledWith(
        expect.objectContaining({
          metadata: expect.objectContaining({
            memscan_evidence_approved: 'true',
          }),
        })
      )
    );
  });
});
