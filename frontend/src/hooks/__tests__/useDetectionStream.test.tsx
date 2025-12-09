import { renderHook, act } from '@testing-library/react';
import { describe, expect, it, beforeEach, afterEach, vi } from 'vitest';
import * as sseModule from '@/services/api/sse';
import { useDetectionStream } from '../useDetectionStream';
import { useDetectionEventStore } from '@/store/detectionEvents';

class TestEventSource {
  onopen: ((this: EventSource, ev: Event) => any) | null = null;

  onmessage: ((this: EventSource, ev: MessageEvent) => any) | null = null;

  onerror: ((this: EventSource, ev: Event) => any) | null = null;

  close = vi.fn();
}

describe('useDetectionStream hook', () => {
  let sources: TestEventSource[];
  let createStreamSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    sources = [];
    useDetectionEventStore.getState().reset();
    createStreamSpy = vi
      .spyOn(sseModule, 'createDetectionEventStream')
      .mockImplementation(() => {
        const source = new TestEventSource();
        sources.push(source);
        return source as unknown as EventSource;
      });
    vi.useFakeTimers();
  });

  afterEach(() => {
    createStreamSpy.mockRestore();
    useDetectionEventStore.getState().reset();
    vi.runOnlyPendingTimers();
    vi.useRealTimers();
  });

  it('updates the store and retries when SSE errors occur', () => {
    const { unmount } = renderHook(() => useDetectionStream());
    expect(createStreamSpy).toHaveBeenCalledTimes(1);

    const firstSource = sources[0];
    expect(firstSource).toBeDefined();

    act(() => {
      firstSource?.onopen?.(new Event('open'));
    });
    expect(useDetectionEventStore.getState().status).toBe('connected');

    const payload = {
      event: 'detection.triggered',
      task_id: '00000000-0000-4000-8000-000000000123',
      task_type: 'detection',
      status: 'high',
      severity: 'high',
      agent_id: '00000000-0000-4000-8000-000000000999',
      metadata: { rule: 'mock-rule' },
      updated_at: new Date().toISOString(),
    };

    act(() => {
      firstSource?.onmessage?.(
        new MessageEvent('message', {
          data: JSON.stringify(payload),
        })
      );
    });
    expect(useDetectionEventStore.getState().events[0]?.task_id).toBe(payload.task_id);

    act(() => {
      firstSource?.onerror?.(new Event('error'));
    });
    expect(firstSource?.close).toHaveBeenCalled();
    expect(useDetectionEventStore.getState().status).toBe('disconnected');

    act(() => {
      vi.advanceTimersByTime(2100);
    });
    expect(createStreamSpy).toHaveBeenCalledTimes(2);

    const secondSource = sources[1];
    expect(secondSource).toBeDefined();

    unmount();
    expect(secondSource?.close).toHaveBeenCalled();
  });
});
