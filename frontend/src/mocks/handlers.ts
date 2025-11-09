import { http, HttpResponse, delay } from 'msw';
import { mockTasks } from './data/tasks';
import { mockReportSummary } from './data/reports';
import { mockTemplates } from './data/templates';
import { mockAuditEvents } from './data/audit';
import { mockAssets } from './data/assets';
import { mockAssetDetails } from './data/assetDetails';
import { mockUsers } from './data/auth';

const API_BASE = '/api/v1';

const respondWithDelay = async (payload: unknown, ms = 320) => {
  await delay(ms);
  return HttpResponse.json(payload as any);
};

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
];
