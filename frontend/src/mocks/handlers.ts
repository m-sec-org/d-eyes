import { http, HttpResponse, delay } from 'msw';
import { mockTasks } from './data/tasks';
import { mockReportSummary } from './data/reports';
import { mockTemplates } from './data/templates';
import { mockAuditEvents } from './data/audit';
import { mockAssets } from './data/assets';
import { mockAssetDetails } from './data/assetDetails';
import { mockUsers } from './data/auth';
import { mockRbacPolicies } from './data/rbac';
import { mockCollectors } from './data/collectors';
import { mockSystemEvents } from './data/systemEvents';

const API_BASE = '/api/v1';

const respondWithDelay = async (payload: unknown, ms = 320) => {
  await delay(ms);
  return HttpResponse.json(payload as any);
};

const parseList = (value?: string | null) =>
  value
    ?.split(',')
    .map((item) => item.trim())
    .filter((item) => item.length > 0) ?? [];

const filterSystemEvents = (url: URL) => {
  const priorities = parseList(url.searchParams.get('priority'));
  const storageTiers = parseList(url.searchParams.get('storage_tier'));
  const collectorKind = url.searchParams.get('collector_kind');
  const eventType = url.searchParams.get('event_type');
  const collector = url.searchParams.get('collector');
  const source = url.searchParams.get('source');
  const agentId = url.searchParams.get('agent_id');
  const since = url.searchParams.get('since');
  const until = url.searchParams.get('until');
  const sinceTs = since ? Date.parse(since) : undefined;
  const untilTs = until ? Date.parse(until) : undefined;

  return mockSystemEvents.filter((event) => {
    if (priorities.length && (!event.priority || !priorities.includes(event.priority))) {
      return false;
    }
    if (storageTiers.length && (!event.storage_tier || !storageTiers.includes(event.storage_tier))) {
      return false;
    }
    if (collectorKind && event.collector_kind !== collectorKind) {
      return false;
    }
    if (eventType && event.event_type !== eventType) {
      return false;
    }
    if (collector && event.collector !== collector) {
      return false;
    }
    if (source && (event.source ?? '') !== source) {
      return false;
    }
    if (agentId && event.agent_id !== agentId) {
      return false;
    }
    const eventTime = Date.parse(event.timestamp);
    if (sinceTs && eventTime < sinceTs) {
      return false;
    }
    if (untilTs && eventTime > untilTs) {
      return false;
    }
    return true;
  });
};

const paginateSystemEvents = (events: typeof mockSystemEvents, url: URL) => {
  const limitParam = Number(url.searchParams.get('limit') ?? '100');
  const limit = Number.isNaN(limitParam) ? 100 : Math.max(1, Math.min(limitParam, 1000));
  const sort = url.searchParams.get('sort') === 'asc' ? 'asc' : 'desc';
  const cursorId = url.searchParams.get('cursor_id');

  const sorted = [...events].sort((a, b) => {
    const aTime = Date.parse(a.received_at);
    const bTime = Date.parse(b.received_at);
    return sort === 'asc' ? aTime - bTime : bTime - aTime;
  });

  let startIndex = 0;
  if (cursorId) {
    const cursorIndex = sorted.findIndex((event) => event.id === cursorId);
    if (cursorIndex >= 0) {
      startIndex = cursorIndex + 1;
    }
  }

  const items = sorted.slice(startIndex, startIndex + limit);
  const hasMore = startIndex + limit < sorted.length;
  const nextCursor =
    hasMore && items.length > 0
      ? {
          id: items[items.length - 1].id,
          received_at: items[items.length - 1].received_at,
        }
      : null;

  return { items, nextCursor };
};

const buildSystemEventStats = (events: typeof mockSystemEvents) =>
  events.reduce(
    (acc, event) => {
      acc.total += 1;
      if (event.event_type) {
        acc.by_event_type[event.event_type] = (acc.by_event_type[event.event_type] ?? 0) + 1;
      }
      if (event.source) {
        acc.by_source[event.source] = (acc.by_source[event.source] ?? 0) + 1;
      }
      return acc;
    },
    { total: 0, by_event_type: {} as Record<string, number>, by_source: {} as Record<string, number> }
  );

export const handlers = [
  http.post(`${API_BASE}/auth/login`, async ({ request }) => {
    const body = await request.json();
    const { username, password } = body as { username: string; password: string };
    const user = mockUsers[username as keyof typeof mockUsers];
    if (!user || user.password !== password) {
      return HttpResponse.json({ message: 'invalid credentials' }, { status: 401 });
    }
    return respondWithDelay({
      token: `mock-token-${username}`,
      refresh_token: `mock-refresh-${username}`,
      expires_in: 1800,
      user: {
        username,
        display_name: user.display_name ?? username,
        role: user.role,
        capabilities: user.capabilities,
      },
    });
  }),
  http.post(`${API_BASE}/auth/refresh`, async ({ request }) => {
    const body = await request.json();
    const { refresh_token } = body as { refresh_token: string };
    const username = refresh_token?.split('-').pop() ?? 'ops.lead';
    const user = mockUsers[username as keyof typeof mockUsers];
    return respondWithDelay({
      token: `mock-token-${username}-refreshed`,
      refresh_token: `mock-refresh-${username}`,
      expires_in: 1800,
      user: {
        username,
        display_name: user?.display_name ?? username,
        role: user?.role ?? 'operator',
        capabilities: user?.capabilities,
      },
    });
  }),
  http.post(`${API_BASE}/auth/logout`, () => HttpResponse.json({ ok: true })),
  http.get(`${API_BASE}/tasks`, async ({ request }) => {
    const url = new URL(request.url);
    const statusFilter = url.searchParams.get('status');
    const filtered =
      statusFilter && statusFilter.length > 0
        ? mockTasks.filter((task) => statusFilter.split(',').includes(task.status))
        : mockTasks;
    return respondWithDelay({ data: filtered });
  }),
  http.get(`${API_BASE}/reports/summary`, async () => respondWithDelay(mockReportSummary)),
  http.get(`${API_BASE}/task-templates`, async () => respondWithDelay(mockTemplates)),
  http.get(`${API_BASE}/audit/events`, async () => respondWithDelay(mockAuditEvents)),
  http.get(`${API_BASE}/assets`, async () => respondWithDelay(mockAssets)),
  http.get(`${API_BASE}/assets/:id`, async ({ params }) => {
    const detail = mockAssetDetails[params.id as string];
    if (!detail) {
      return HttpResponse.json({ message: 'not found' }, { status: 404 });
    }
    return respondWithDelay(detail);
  }),
  http.post(`${API_BASE}/tasks`, async ({ request }) => {
    const body = (await request.json()) as any;
    const newTask = {
      id: crypto.randomUUID(),
      type: body.type ?? 'respond',
      profile: body.profile ?? 'default',
      priority: body.priority ?? 3,
      status: 'pending',
      retry_count: 0,
      metadata: body.metadata ?? {},
      created_by: body.created_by ?? 'mock.user',
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    };
    mockTasks.unshift(newTask as any);
    return respondWithDelay({ id: newTask.id }, 200);
  }),
  http.post(`${API_BASE}/tasks/:id/retry`, async ({ params }) => {
    const task = mockTasks.find((t) => t.id === params.id);
    if (!task) {
      return HttpResponse.json({ message: 'not found' }, { status: 404 });
    }
    task.retry_count = (task.retry_count ?? 0) + 1;
    task.status = 'pending';
    task.updated_at = new Date().toISOString();
    return respondWithDelay(task);
  }),
  http.post(`${API_BASE}/tasks/:id/cancel`, async ({ params }) => {
    const task = mockTasks.find((t) => t.id === params.id);
    if (!task) {
      return HttpResponse.json({ message: 'not found' }, { status: 404 });
    }
    task.status = 'canceled';
    task.updated_at = new Date().toISOString();
    return respondWithDelay(task);
  }),
  http.post(`${API_BASE}/assets/batch-tag`, async ({ request }) => {
    const body = (await request.json()) as { ids: string[]; tag: string };
    body.ids.forEach((id) => {
      const asset = mockAssets.items.find((item) => item.id === id);
      if (asset && !asset.tags.includes(body.tag)) {
        asset.tags.push(body.tag);
      }
      const detail = mockAssetDetails[id];
      if (detail && !detail.tags.includes(body.tag)) {
        detail.tags.push(body.tag);
      }
    });
    return respondWithDelay({ ids: body.ids, tag: body.tag });
  }),
  http.get(`${API_BASE}/events`, async ({ request }) => {
    const url = new URL(request.url);
    const filtered = filterSystemEvents(url);
    const { items, nextCursor } = paginateSystemEvents(filtered, url);
    return respondWithDelay({ items, next_cursor: nextCursor });
  }),
  http.get(`${API_BASE}/events/stats`, async ({ request }) => {
    const url = new URL(request.url);
    const filtered = filterSystemEvents(url);
    const stats = buildSystemEventStats(filtered);
    return respondWithDelay(stats);
  }),
  http.get(`${API_BASE}/collectors`, async () => respondWithDelay(mockCollectors)),
  http.patch(`${API_BASE}/collectors/:id`, async ({ params, request }) => {
    const body = (await request.json()) as Record<string, unknown>;
    const index = mockCollectors.findIndex((collector) => collector.id === params.id);
    if (index === -1) {
      return HttpResponse.json({ message: 'not found' }, { status: 404 });
    }
    mockCollectors[index] = {
      ...mockCollectors[index],
      ...body,
    };
    return respondWithDelay(mockCollectors[index]);
  }),
  http.get(`${API_BASE}/rbac/policies`, async () => respondWithDelay({ policies: mockRbacPolicies })),
];
