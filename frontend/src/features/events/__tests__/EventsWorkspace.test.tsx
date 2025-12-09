import { render, screen, waitFor, within, cleanup } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { SWRConfig } from 'swr';
import { describe, expect, it, beforeEach, afterEach, vi } from 'vitest';
import { EventsWorkspace } from '../EventsWorkspace';
import { useSystemEventStore } from '@/store/systemEvents';
import { useDetectionEventStore } from '@/store/detectionEvents';
import { mockDetectionEvents } from '@/mocks/data/detectionEvents';
import { mockCollectors } from '@/mocks/data/collectors';
import * as taskActions from '@/services/api/taskActions';
import * as collectorApi from '@/services/api/collectors';

vi.mock('@/hooks/useDetectionStream', () => ({
  useDetectionStream: vi.fn(),
}));

const renderWorkspace = () => {
  const cache = new Map();
  return render(
    <MemoryRouter initialEntries={['/events']}>
      <SWRConfig value={{ provider: () => cache, dedupingInterval: 0 }}>
        <EventsWorkspace />
      </SWRConfig>
    </MemoryRouter>
  );
};

describe('EventsWorkspace', () => {
  const createTaskSpy = vi.spyOn(taskActions, 'createTask').mockResolvedValue({ id: 'task-1' });
  const updateCollectorSpy = vi
    .spyOn(collectorApi, 'updateCollectorConfig')
    .mockImplementation(async (collectorId, payload) => ({
      ...mockCollectors.find((item) => item.id === collectorId)!,
      ...payload,
    }));

  beforeEach(() => {
    useSystemEventStore.getState().reset();
    useDetectionEventStore.getState().reset();
    useDetectionEventStore.setState({
      status: 'connected',
      events: mockDetectionEvents,
      windowSize: 320,
    });
  });

  afterEach(() => {
    cleanup();
    useSystemEventStore.getState().reset();
    useDetectionEventStore.getState().reset();
    createTaskSpy.mockClear();
    updateCollectorSpy.mockClear();
  });

  afterAll(() => {
    createTaskSpy.mockRestore();
    updateCollectorSpy.mockRestore();
  });

  it('renders workspace widgets and triggers respond/collector actions', async () => {
    const user = userEvent.setup();
    renderWorkspace();

    expect(await screen.findByLabelText('事件过滤条件')).toBeInTheDocument();
    expect(await screen.findByLabelText('事件时间线')).toBeInTheDocument();
    expect(await screen.findByLabelText('事件热图')).toBeInTheDocument();
    expect(await screen.findByLabelText('collector 控制面')).toBeInTheDocument();
    expect(await screen.findByLabelText('respond 快捷操作')).toBeInTheDocument();

    await waitFor(() => expect(screen.getByText(/process\.exec/i)).toBeInTheDocument());

    const statsCard = await screen.findByLabelText('事件统计');
    expect(within(statsCard).getByText('累计事件')).toBeInTheDocument();
    expect(within(statsCard).getAllByText('6').length).toBeGreaterThan(0);

    const detectionCard = await screen.findByLabelText('实时检测告警');
    expect(within(detectionCard).getByText(/PowerShell script block/i)).toBeInTheDocument();
    expect(within(detectionCard).getByText(/SSE: connected/i)).toBeInTheDocument();

    const respondCard = await screen.findByLabelText('respond 快捷操作');
    const quickButton = within(respondCard).getAllByRole('button', { name: '触发 Respond' })[0];
    await user.click(quickButton);
    await waitFor(() => expect(createTaskSpy).toHaveBeenCalledTimes(1));

    const detectionButton = within(detectionCard).getAllByRole('button', { name: '触发 Respond' })[0];
    await user.click(detectionButton);
    await waitFor(() => expect(createTaskSpy).toHaveBeenCalledTimes(2));

    const collectorCard = await screen.findByLabelText('collector 控制面');
    const saveButton = within(collectorCard).getByRole('button', { name: '保存配置' });
    await user.click(saveButton);
    await waitFor(() => expect(updateCollectorSpy).toHaveBeenCalled());
  });
});
