import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach, vi } from 'vitest';
import { SWRConfig } from 'swr';
import { message, type TableProps } from 'antd';
import { AuditLogView } from '../AuditLogView';
import { listAuditEvents } from '@/services/api/audit';

vi.mock('@/services/api/audit', () => ({
  listAuditEvents: vi.fn(),
}));

vi.mock('@/components/OperationTimeline', () => ({
  OperationTimeline: () => <div data-testid="timeline" />,
}));

vi.mock('antd', async (importOriginal) => {
  const actual = await importOriginal<typeof import('antd')>();
  const MockTable = (props: TableProps<any>) => (
    <div data-testid="audit-table">
      <div data-testid="audit-table-rows">
        {(props.dataSource ?? []).map((row: any) => (
          <div key={row.key ?? row.id}>{row.action}</div>
        ))}
      </div>
      <button
        type="button"
        onClick={() =>
          props.onChange?.(
            { ...(props.pagination ?? {}), current: 2 } as any,
            {},
            { field: 'timestamp', order: 'descend' } as any
          )
        }
      >
        下一页
      </button>
    </div>
  );
  return { ...actual, Table: MockTable };
});

const buildEvent = (index: number) => {
  const label = index.toString().padStart(2, '0');
  return {
    id: `evt-${label}`,
    timestamp: new Date(2024, 0, index + 1).toISOString(),
    actor: `actor-${label}`,
    role: 'admin',
    action: `action-${label}`,
    resource: `resource-${label}`,
    result: 'success',
  };
};

const renderAudit = () =>
  render(
    <SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0, revalidateOnFocus: false }}>
      <AuditLogView />
    </SWRConfig>
  );

describe('AuditLogView', () => {
  const originalResizeObserver = globalThis.ResizeObserver;

  beforeAll(() => {
    (globalThis as any).ResizeObserver =
      class {
        observe() {}
        unobserve() {}
        disconnect() {}
      };
  });

  afterAll(() => {
    if (originalResizeObserver) {
      (globalThis as any).ResizeObserver = originalResizeObserver;
    } else {
      delete (globalThis as any).ResizeObserver;
    }
  });

  beforeEach(() => {
    (listAuditEvents as unknown as vi.Mock).mockResolvedValue({ items: [buildEvent(1), buildEvent(2)] });
  });

  afterEach(() => {
    vi.clearAllMocks();
    vi.restoreAllMocks();
  });

  it('submits filter values and refetches audit events', async () => {
    const user = userEvent.setup();
    renderAudit();
    await waitFor(() => expect(listAuditEvents).toHaveBeenCalled());
    (listAuditEvents as unknown as vi.Mock).mockClear();
    await user.type(screen.getByPlaceholderText('操作人'), 'alice');
    await user.type(screen.getByPlaceholderText('资源关键词'), 'db');
    await user.type(screen.getByPlaceholderText('行为关键词'), 'login');
    await user.click(screen.getByRole('button', { name: /查.?询/ }));
    await waitFor(() =>
      expect(listAuditEvents).toHaveBeenCalledWith({
        actor: 'alice',
        resource: 'db',
        action: 'login',
        limit: 200,
      })
    );
  });

  it('shows older events when switching to the next pagination page', async () => {
    const events = Array.from({ length: 23 }, (_, index) => buildEvent(index + 1));
    (listAuditEvents as unknown as vi.Mock).mockResolvedValue({ items: events });
    const user = userEvent.setup();
    renderAudit();
    await waitFor(() => expect(screen.getByText('action-23')).toBeInTheDocument());
    await waitFor(() => expect(screen.queryByText('action-03')).not.toBeInTheDocument());
    const nextPageButton = await screen.findByRole('button', { name: '下一页' });
    await user.click(nextPageButton);
    await waitFor(() => expect(screen.getByText('action-03')).toBeInTheDocument());
  });

  it('shows error alert when audit API fails', async () => {
    (listAuditEvents as unknown as vi.Mock).mockRejectedValueOnce(new Error('network down'));
    renderAudit();
    await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent('network down'));
  });

  it('exports JSON and notifies user with AntD message', async () => {
    const user = userEvent.setup();
    const successSpy = vi.spyOn(message, 'success').mockImplementation(() => undefined);
    const objectUrlSpy = vi.spyOn(URL, 'createObjectURL').mockReturnValue('blob:mock');
    const revokeSpy = vi.spyOn(URL, 'revokeObjectURL').mockReturnValue(undefined);
    const clickSpy = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {});
    renderAudit();
    await waitFor(() => expect(screen.getByText('action-01')).toBeInTheDocument());
    await user.click(screen.getByRole('button', { name: '导出 JSON' }));
    await waitFor(() => expect(successSpy).toHaveBeenCalledWith('已导出 2 条审计记录'));
    expect(objectUrlSpy).toHaveBeenCalled();
    expect(revokeSpy).toHaveBeenCalled();
    expect(clickSpy).toHaveBeenCalled();
    successSpy.mockRestore();
  });
});
