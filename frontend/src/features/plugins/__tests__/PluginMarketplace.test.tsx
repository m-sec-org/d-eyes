import { act, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, it, beforeAll, afterAll, beforeEach, afterEach, expect, vi } from 'vitest';
import { message, Modal } from 'antd';
import { PluginMarketplace } from '../PluginMarketplace';
import { listPlugins, installPlugin, rollbackPlugin } from '@/services/api/plugins';

class MockEventSource {
  static instances: MockEventSource[] = [];
  url: string;
  onmessage: ((event: MessageEvent) => void) | null = null;
  onerror: ((event: MessageEvent) => void) | null = null;
  close = vi.fn();

  constructor(url: string) {
    this.url = url;
    MockEventSource.instances.push(this);
  }

  emit(data: unknown) {
    this.onmessage?.({ data: JSON.stringify(data) } as MessageEvent);
  }
}

const setupMessageMock = () => {
  const api = {
    success: vi.fn(),
    error: vi.fn(),
    info: vi.fn(),
    warning: vi.fn(),
    loading: vi.fn(() => vi.fn()),
    destroy: vi.fn(),
  };
  vi.spyOn(message, 'useMessage').mockReturnValue([api, <div data-testid="message-holder" />]);
  return api;
};

const buildPlugin = (index: number) => ({
  manifest: {
    name: `plugin-${index}`,
    version: `1.0.${index}`,
    description: `desc-${index}`,
  },
  status: index % 2 === 0 ? 'running' : 'failed',
  reason: index % 2 === 0 ? undefined : 'crashed',
  installed_at: `2024-02-${(index % 28) + 1}T00:00:00Z`,
});

vi.mock('@/services/api/plugins', () => ({
  listPlugins: vi.fn(),
  installPlugin: vi.fn(),
  rollbackPlugin: vi.fn(),
}));

describe('PluginMarketplace', () => {
  const originalEventSource = globalThis.EventSource;
  const originalResizeObserver = globalThis.ResizeObserver;
  let messageApi: ReturnType<typeof setupMessageMock>;

  beforeAll(() => {
    (globalThis as any).EventSource = MockEventSource;
    (globalThis as any).ResizeObserver =
      class {
        observe() {}
        unobserve() {}
        disconnect() {}
      };
  });

  afterAll(() => {
    if (originalEventSource) {
      (globalThis as any).EventSource = originalEventSource;
    } else {
      delete (globalThis as any).EventSource;
    }
    if (originalResizeObserver) {
      (globalThis as any).ResizeObserver = originalResizeObserver;
    } else {
      delete (globalThis as any).ResizeObserver;
    }
  });

  beforeEach(() => {
    MockEventSource.instances = [];
    messageApi = setupMessageMock();
    (listPlugins as unknown as vi.Mock).mockResolvedValue([buildPlugin(1), buildPlugin(2)]);
    (installPlugin as unknown as vi.Mock).mockResolvedValue(undefined);
    (rollbackPlugin as unknown as vi.Mock).mockResolvedValue(undefined);
  });

  afterEach(() => {
    vi.clearAllMocks();
    vi.restoreAllMocks();
  });

  it('renders plugin rows and paginates 8 items per page', async () => {
    const plugins = Array.from({ length: 10 }, (_, index) => buildPlugin(index + 1));
    (listPlugins as unknown as vi.Mock).mockResolvedValueOnce(plugins);
    const { container } = render(<PluginMarketplace />);
    await waitFor(() => expect(screen.getByText('plugin-1')).toBeInTheDocument());
    const rows = container.querySelectorAll('.ant-table-tbody tr');
    expect(rows.length).toBe(8);
  });

  it('installs plugin manifest through the form', async () => {
    const user = userEvent.setup();
    render(<PluginMarketplace />);
    await waitFor(() => expect(screen.getByText('插件市场')).toBeInTheDocument());
    const textarea = screen.getByPlaceholderText('粘贴插件 manifest (YAML)');
    await user.type(textarea, 'name: demo');
    await user.click(screen.getByRole('button', { name: '安装 / 升级' }));
    await waitFor(() => expect(installPlugin).toHaveBeenCalledWith('name: demo', 'plain'));
    expect(messageApi.success).toHaveBeenCalledWith('插件安装/升级成功');
    expect(listPlugins).toHaveBeenCalledTimes(2); // initial + refresh
  });

  it('shows error alert when loading plugins fails', async () => {
    (listPlugins as unknown as vi.Mock).mockRejectedValueOnce(new Error('boom'));
    render(<PluginMarketplace />);
    await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent('获取插件列表失败'));
  });

  it('surfaces install failure message', async () => {
    const user = userEvent.setup();
    (installPlugin as unknown as vi.Mock).mockRejectedValueOnce({ response: { data: { error: 'bad manifest' } } });
    render(<PluginMarketplace />);
    await waitFor(() => expect(screen.getByText('插件市场')).toBeInTheDocument());
    await user.type(screen.getByPlaceholderText('粘贴插件 manifest (YAML)'), 'err');
    await user.click(screen.getByRole('button', { name: '安装 / 升级' }));
    await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent('bad manifest'));
  });

  it('refetches plugins when SSE emits events and closes stream on unmount', async () => {
    const { unmount } = render(<PluginMarketplace />);
    await waitFor(() => expect(screen.getByText('插件市场')).toBeInTheDocument());
    (listPlugins as unknown as vi.Mock).mockClear();
    const source = MockEventSource.instances[0];
    act(() => {
      source.emit({ event: 'plugin.updated' });
    });
    await waitFor(() => expect(listPlugins).toHaveBeenCalled());
    unmount();
    expect(source.close).toHaveBeenCalled();
  });

  it('rolls back a plugin with confirmation', async () => {
    const user = userEvent.setup();
    const modalSpy = vi.spyOn(Modal, 'confirm').mockImplementation((config: any) => {
      config?.onOk?.();
      return {} as any;
    });
    render(<PluginMarketplace />);
    await waitFor(() => expect(screen.getByText('插件市场')).toBeInTheDocument());
    const rollbackButton = screen.getAllByRole('button', { name: /回.?滚/ })[0];
    await user.click(rollbackButton);
    await waitFor(() => expect(rollbackPlugin).toHaveBeenCalled());
    expect(messageApi.success).toHaveBeenCalledWith('插件已回滚');
    expect(listPlugins).toHaveBeenCalledTimes(2);
    modalSpy.mockRestore();
  });
});
