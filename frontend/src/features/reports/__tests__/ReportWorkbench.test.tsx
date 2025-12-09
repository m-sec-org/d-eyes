import { render, screen, within, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { SWRConfig } from 'swr';
import { describe, it, vi, expect, beforeEach, afterEach } from 'vitest';
import { message, Modal } from 'antd';
import { ReportWorkbench } from '../ReportWorkbench';

const templatesMock = [
  {
    id: 'tpl-1',
    name: 'HTML 模板',
    format: 'html',
    body: '<h1>{{ .task.ID }}</h1>',
    updated_at: '2024-01-01T00:00:00Z',
  },
  {
    id: 'tpl-2',
    name: 'JSON 模板',
    format: 'json',
    body: '{ "id": "{{ .task.ID }}" }',
    updated_at: '2024-01-02T00:00:00Z',
  },
];

const reportApiMocks = {
  listReportTemplates: vi.fn(async () => templatesMock),
  createReportTemplate: vi.fn(),
  updateReportTemplate: vi.fn(),
  deleteReportTemplate: vi.fn(),
  generateReport: vi.fn(async () => new Blob(['{}'], { type: 'application/json' })),
};

vi.mock('@/services/api/reportTemplates', () => reportApiMocks);

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

const renderComponent = () =>
  render(
    <SWRConfig value={{ provider: () => new Map() }}>
      <ReportWorkbench />
    </SWRConfig>
  );

describe('ReportWorkbench table interactions', () => {
  beforeEach(() => {
    setupMessageMock();
    reportApiMocks.deleteReportTemplate.mockClear();
    reportApiMocks.generateReport.mockClear();
    global.ResizeObserver = class {
      observe() {}
      unobserve() {}
      disconnect() {}
    };
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('shows bulk toolbar after selecting template', async () => {
    const user = userEvent.setup();
    renderComponent();
    const table = await screen.findByTestId('report-template-table');
    const checkboxes = within(table).getAllByRole('checkbox');
    await user.click(checkboxes[1]);
    expect(await screen.findByText('已选 1 个模板')).toBeInTheDocument();
  });

  it('adds download history after generating report', async () => {
    const user = userEvent.setup();
    const createObjectURL = vi.spyOn(URL, 'createObjectURL').mockReturnValue('blob:mock');
    vi.spyOn(URL, 'revokeObjectURL').mockReturnValue(undefined);
    vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {});
    renderComponent();

    await user.click(await screen.findByRole('button', { name: '编辑' }));
    const taskInput = screen.getByPlaceholderText('任务 ID');
    await user.type(taskInput, 'task-123');
    await user.click(screen.getByRole('button', { name: '生成' }));

    const history = await screen.findByTestId('report-download-history');
    expect(history).toHaveTextContent('task-123');
    expect(createObjectURL).toHaveBeenCalled();
  });

  it('calls delete API when confirming bulk delete', async () => {
    const user = userEvent.setup();
    const modalSpy = vi.spyOn(Modal, 'confirm').mockImplementation((config: any) => {
      config?.onOk?.();
      return {} as any;
    });
    renderComponent();
    const table = await screen.findByTestId('report-template-table');
    const checkboxes = within(table).getAllByRole('checkbox');
    await user.click(checkboxes[0]);
    await user.click(screen.getByRole('button', { name: '批量删除' }));
    await waitFor(() => expect(reportApiMocks.deleteReportTemplate).toHaveBeenCalledTimes(templatesMock.length));
    modalSpy.mockRestore();
  });
});
