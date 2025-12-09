import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { SWRConfig } from 'swr';
import { message } from 'antd';
import { SystemConfigCenter } from '../SystemConfigCenter';
import { bulkDeployTemplates, bulkDeleteTemplates } from '@/services/api/templates';

const templatesMock = [
  {
    id: 'tpl-1',
    name: '高危巡检',
    task_type: 'detect',
    priority: 5,
    schedule: { enabled: true, interval_minutes: 15 },
  },
];

const policiesMock = [
  { role: 'secops', permissions: ['read', 'write'] },
  { role: 'viewer', permissions: ['read'] },
];

vi.mock('@/services/api/templates', () => ({
  listTemplates: vi.fn(async () => templatesMock),
  bulkDeployTemplates: vi.fn(async () => undefined),
  bulkDeleteTemplates: vi.fn(async () => undefined),
}));

vi.mock('@/services/api/rbac', () => ({
  listRbacPolicies: vi.fn(async () => policiesMock),
}));

const setupMessageMock = () => {
  const messageApi = {
    loading: vi.fn(() => vi.fn()),
    success: vi.fn(),
    info: vi.fn(),
    warning: vi.fn(),
    destroy: vi.fn(),
  };
  vi.spyOn(message, 'useMessage').mockReturnValue([messageApi, <div data-testid="message-holder" />]);
  return messageApi;
};

const renderWithProviders = () =>
  render(
    <SWRConfig value={{ provider: () => new Map() }}>
      <SystemConfigCenter />
    </SWRConfig>
  );

describe('SystemConfigCenter', () => {
  let messageApiRef: ReturnType<typeof setupMessageMock>;

  beforeEach(() => {
    messageApiRef = setupMessageMock();
    (bulkDeployTemplates as unknown as vi.Mock).mockClear();
    (bulkDeleteTemplates as unknown as vi.Mock).mockClear();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('renders template table and global config form', async () => {
    renderWithProviders();
    await waitFor(() => expect(screen.getByText('系统配置中心')).toBeInTheDocument());
    expect(screen.getByLabelText(/风险阈值/)).toBeInTheDocument();
    expect(screen.getByText(/任务模板/)).toBeInTheDocument();
  });

  it('calls deploy API when selecting template and clicking deploy', async () => {
    const user = userEvent.setup();
    renderWithProviders();
    const section = await screen.findByTestId('template-table-section');
    const checkboxes = within(section).getAllByRole('checkbox');
    await user.click(checkboxes[1]);
    expect(await screen.findByText('已选 1 个模板')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: '批量部署' }));
    await waitFor(() => expect(screen.queryByText('已选 1 个模板')).not.toBeInTheDocument());
    expect(bulkDeployTemplates).toHaveBeenCalledWith(['tpl-1']);
  });

  it('calls delete API when clicking bulk delete', async () => {
    const user = userEvent.setup();
    renderWithProviders();
    const section = await screen.findByTestId('template-table-section');
    const checkboxes = within(section).getAllByRole('checkbox');
    await user.click(checkboxes[1]);
    await user.click(screen.getByRole('button', { name: '批量删除' }));
    await waitFor(() => expect(bulkDeleteTemplates).toHaveBeenCalledWith(['tpl-1']));
  });

  it('invokes loading message when saving config', async () => {
    const user = userEvent.setup();
    vi.useFakeTimers();
    renderWithProviders();
    await user.click(screen.getByRole('button', { name: '保存配置' }));
    expect(messageApiRef.loading).toHaveBeenCalledTimes(1);
    vi.runAllTimers();
    await waitFor(() => expect(messageApiRef.success).toHaveBeenCalled());
    vi.useRealTimers();
  });
});
