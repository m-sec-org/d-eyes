import { describe, expect, test, beforeEach, afterEach } from 'vitest';
import { act } from 'react';
import { render, cleanup } from '@testing-library/react';
import { randomUUID } from 'node:crypto';
import { TaskLiveMonitor } from '@/features/tasks/components/TaskLiveMonitor';
import { useTaskEventStore } from '@/store/taskEvents';
import type { Task } from '@/services/types';
import { MockTaskEventSource } from '@/mocks/mockEventSource';

function createMockTasks(count: number): Task[] {
  return Array.from({ length: count }).map((_, index) => {
    const id = randomUUID();
    return {
      id,
      type: index % 2 === 0 ? 'respond' : 'baseline',
      priority: 5,
      status: index % 3 === 0 ? 'running' : 'pending',
      created_at: new Date(Date.now() - 1000 * 60 * (index + 1)).toISOString(),
      updated_at: new Date().toISOString(),
      last_run: null,
    };
  });
}

function createMockEvent(index: number) {
  const id = randomUUID();
  return {
    event: index % 4 === 0 ? 'running' : 'progress',
    task_id: id,
    task_type: index % 2 === 0 ? 'respond' : 'baseline',
    status: index % 4 === 0 ? 'running' : 'leased',
    agent_id: randomUUID(),
    severity: index % 15 === 0 ? 'danger' : index % 5 === 0 ? 'warning' : 'info',
    progress: (index * 7) % 100,
    updated_at: new Date(Date.now() + index).toISOString(),
    message: `event-${index}`,
  };
}

const mockTasks = createMockTasks(40);

describe('Task Command Center baseline diagnostics', () => {
  beforeEach(() => {
    MockTaskEventSource.intervalMs = 200;
    useTaskEventStore.setState({ status: 'connected', events: [] });
  });

  afterEach(() => {
    cleanup();
    useTaskEventStore.setState({ status: 'connecting', events: [] });
  });

  test('task stream mock emits expected interval', async () => {
    const intervals: number[] = [];
    const source = new MockTaskEventSource();
    let last = performance.now();

    await new Promise<void>((resolve) => {
      source.onmessage = () => {
        const now = performance.now();
        intervals.push(now - last);
        last = now;
        if (intervals.length >= 8) {
          source.close();
          resolve();
        }
      };
    });

    const avgInterval = intervals.reduce((sum, value) => sum + value, 0) / intervals.length;
    const minInterval = Math.min(...intervals);
    const maxInterval = Math.max(...intervals);

    // Log metrics for the diagnostics doc.
    console.info(
      `[baseline] SSE intervals -> avg: ${avgInterval.toFixed(1)}ms | min: ${minInterval.toFixed(
        1
      )}ms | max: ${maxInterval.toFixed(1)}ms`
    );

    expect(avgInterval).toBeGreaterThanOrEqual(150);
    expect(avgInterval).toBeLessThanOrEqual(260);
  });

  test('live monitor render cost without virtualization', () => {
    const { container } = render(<TaskLiveMonitor tasks={mockTasks} />);
    const durations: number[] = [];
    const addEvent = useTaskEventStore.getState().addEvent;

    act(() => {
      for (let i = 0; i < 600; i += 1) {
        const start = performance.now();
        addEvent(createMockEvent(i));
        durations.push(performance.now() - start);
      }
    });

    const total = durations.reduce((sum, value) => sum + value, 0);
    const avg = total / durations.length;
    const sorted = [...durations].sort((a, b) => a - b);
    const p95 = sorted[Math.floor(sorted.length * 0.95)];
    const rows = container.querySelectorAll('[data-testid=\"live-monitor-row\"]').length;
    const domNodes = container.querySelectorAll('*').length;

    console.info(
      `[baseline] Render metrics -> rows: ${rows}, domNodes: ${domNodes}, avg render: ${avg.toFixed(
        3
      )}ms, p95: ${p95.toFixed(3)}ms`
    );

    expect(rows).toBeGreaterThan(0);
    expect(rows).toBeLessThanOrEqual(40);
    expect(domNodes).toBeLessThan(220);
  });
});
