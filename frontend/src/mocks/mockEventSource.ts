import { mockTaskEvents } from './data/taskEvents';

const CONNECTING = 0;
const OPEN = 1;
const CLOSED = 2;

type Timer = ReturnType<typeof setTimeout>;

export class MockTaskEventSource extends EventTarget {
  readonly CONNECTING = CONNECTING;

  readonly OPEN = OPEN;

  readonly CLOSED = CLOSED;

  url = 'mock://task-stream';

  withCredentials = false;

  readyState: number = CONNECTING;

  onopen: ((this: EventSource, ev: Event) => any) | null = null;

  onmessage: ((this: EventSource, ev: MessageEvent) => any) | null = null;

  onerror: ((this: EventSource, ev: Event) => any) | null = null;

  private timer?: Timer;

  private index = 0;

  constructor() {
    super();
    this.start();
  }

  private start() {
    this.readyState = OPEN;
    const openEvent = new Event('open');
    this.onopen?.call(this as unknown as EventSource, openEvent);
    this.dispatchEvent(openEvent);
    this.pushNext();
  }

  private pushNext() {
    this.timer = globalThis.setTimeout(() => {
      const payload = mockTaskEvents[this.index % mockTaskEvents.length];
      const event = new MessageEvent('message', { data: JSON.stringify(payload) });
      this.onmessage?.call(this as unknown as EventSource, event);
      this.dispatchEvent(event);
      this.index += 1;
      this.pushNext();
    }, MockTaskEventSource.intervalMs);
  }

  close(): void {
    if (this.timer) {
      clearTimeout(this.timer);
    }
    this.readyState = CLOSED;
    this.dispatchEvent(new Event('close'));
  }

  static intervalMs = 1500;
}
