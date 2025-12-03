# 1.1 Contract & Data Audit

Task 1.1 requires a concrete inventory of the data dependencies for the three console views that are covered by this change (`TaskOverview`, `QueueMonitor`, `ThreatIntelWorkspace`). This note captures the current frontend usage (`services/api`, SWR hooks, SSE clients), the server handlers that back them, and the exact fields/filters/pagination expectations so that the follow-up tasks can close the gaps.

## Task Command Center (`/tasks`)

### Frontend data inputs

- `listTasks` (`frontend/src/services/api/tasks.ts`): wraps `GET /api/v1/tasks`, accepts `{status, limit, type}` and currently parses the server response as a bare `Task[]`.
- `useTasksData` (`frontend/src/features/tasks/hooks/useTasksData.ts`): SWR hook keyed by `['tasks', statusParam]`. It maps `status=running` to `"running,leased"`, calls `listTasks`, then applies client-side filtering over `task.id`, `task.type`, `task.metadata.targets`, `task.metadata.scenario_id`. There is **no** pagination or cursor handling; Ant Design's table paginates the already-fetched slice.
- `useTaskFilters` (`frontend/src/features/tasks/hooks/useTaskFilters.ts`): stores `{status, search, savedView}` plus saved view definitions inside `localStorage`. These filters never reach the backend today.
- `useTaskActions` + `taskActions.ts`: call `POST /tasks/:id/retry`, `POST /tasks/:id/cancel`, and `POST /tasks/:id/actions` (`performTaskAction`) to drive inline actions from the list and live monitor.
- `TaskDetailDrawer` uses `fetchTaskVisuals` (`frontend/src/services/api/taskVisuals.ts`) to hit `GET /tasks/:id/visuals?type=...` and expects `{items: TaskVisual[]}` (falls back to a raw array for legacy responses).
- `TaskLiveMonitor` consumes SSE via `useTaskStream`/`createTaskEventStream` (`frontend/src/hooks/useTaskStream.ts`, `frontend/src/services/api/sse.ts`) and renders the events stored in `useTaskEventStore`.

### UI widgets & required fields

| Widget/Hook | Fields Needed (source) | Notes |
| --- | --- | --- |
| `TaskBoard` stats (`TaskOverview.tsx`) | `Task.status` | Counts `pending`, `running` (also treats `leased` as running), `failed`. |
| `TaskList` table | `Task.id`, `Task.type`, `Task.status`, `Task.priority`, `Task.metadata.targets`, `Task.metadata.scenario_id`, `Task.updated_at` | Table paginates locally (page size 10) over the entire dataset returned by `listTasks`. |
| `TaskFilters` | `status` options (`all/pending/running/succeeded/failed`), text `search`, saved view metadata (`id`, `name`, `filters`) | Saved views are only persisted on the client; spec calls for `/task-views` APIs to persist per user. |
| `TaskDetailDrawer` | `Task.profile`, `Task.created_by`, timestamps, `Task.metadata`, `Task.last_run.summary`, `Task.last_run.metadata`, `Task.last_run.exit_code`, `Task.last_run.error_code`, plus `TaskVisuals[].payload` | Drawer expects nested summary fields (`summary.duration_seconds`, `summary.risks`, `summary.notes`, `summary.outputs`) and Visuals payloads for charts. |
| `TaskLiveMonitor` | SSE `TaskEvent` fields: `task_id`, `task_type`, `status`, `severity`, `progress`, `message`, `action`, `actor`, `updated_at`; optional queue metrics `queue_depth`, `in_flight`, `bas_in_flight`, `bas_queue_depth` | Also triggers `performTaskAction(taskId, action)` for pause/resume/terminate. Needs reliable SSE status for connection state pills. |

### Filter & pagination expectations

- Status filter must support multi-select combinations (`running` tab expects `running,leased`; the UI spec also calls for `running,failed` combos).
- Keyword search currently runs on the client (ID/type/targets/scenario), but spec requires server-side search for correctness and pagination.
- Local pagination is just AntD table state; the API must return `data`, `page_size`, `next_cursor`, `applied_filters` to enable real pagination & view saving.
- Saved views (`saveCurrentView`, `applyView`) should be persisted via `/api/v1/task-views` with `{filters, page_size, cursor}` per user.

### Server snapshot

- `GET /api/v1/tasks` (`server/internal/api/v1/tasks.go::listTasks`) reads `limit` (default 20) and a comma-separated `status`, then forwards to `store.ListTasks`.
- `store.ListTasks` (Postgres & memory stores) only filters by statuses and sorts by `created_at DESC`. There is no cursor, no search, and no multi-field filters.
- The handler returns a bare JSON array of tasks; there is no `{data, page_size, next_cursor}` envelope, so the frontend currently has to shape the data manually.
- `TaskVisuals` endpoint already returns `{items: []}` but the client keeps a fallback to raw arrays to stay compatible with older responses.

### Identified gaps

- API response mismatch: frontend `useTasksData` expects `data: Task[]` while server returns `[]`.
- Missing `page_size`, `next_cursor`, and serialized `filters` for view saving/replay.
- No backend support for keyword search, metadata filters, or multi-state preset logic (`running` tab needs `running` + `leased`).
- Saved views are client-only; `/api/v1/task-views` CRUD + persistence is absent.
- SSE exists but queue depth / progress fields are often `0` because scheduler never writes them for many task types; this becomes critical when TaskLiveMonitor surfaces anomalies.

## Queue Monitor (`/queues`)

### Frontend state

- `QueueMonitor.tsx` renders `MOCK_QUEUE` data with `{id, taskType, status, priority, agent, updatedAt}`. There is no SWR hook or API call; `handleRefresh` just reuses existing mock data.
- Timeline & table both consume the same array; there are no filters or pagination controls today, just a refresh button and a "view troubleshooting docs" link.
- The UI expects future integration with `/api/v1/queues/summary` plus an SSE stream for live events (see spec requirement).

### Field expectations

| Widget | Fields Needed | Notes |
| --- | --- | --- |
| Queue table | `task_id`, `task_type`, `status (pending/running/blocked)`, `priority`, `agent`, `updated_at` | Table needs real queue depth & agent assignment to explain blocking. |
| Timeline | Same as table plus event ordering | Colors/severity derived from `status`. |
| Alert banner | Needs connection/SSE health + explanation when data is mock/offline. |

### Server snapshot & gaps

- There is no `/queues/summary`, `/queues/stream`, or `/queues/summary` handler in `server/internal/api/v1`. Scheduler exposes queue depth metrics internally, but nothing is available over HTTP/SSE.
- Without a backend API, the frontend cannot transition away from `MOCK_QUEUE`, nor can it display real-time blocked reason / agent ownership.
- Pagination is not yet relevant (table is expected to show "latest snapshot"), but the summary endpoint still needs to surface `page_size` or chunking if the queue grows large.

## Threat Intel Workspace (`/threat-intel`)

### Frontend data inputs

- `lookupIndicator` (`frontend/src/services/api/threatIntel.ts`): `POST /threat-intel/lookup` with `{indicator, kind, sources[], force}`. Response uses `{job_ids: string[], cached?: boolean, verdicts?: Verdict[]}`.
- `fetchIndicator(indicator)` and `fetchSample(sampleId)` call `GET /threat-intel/iocs/{indicator}` and `GET /threat-intel/samples/{id}` respectively; both are consumed through SWR for caching/resynchronization with `activeIndicator` and `selectedSampleId`.
- `listAuditEvents({ action: 'threatintel', limit: 25 })` pulls `/audit/events` into the audit table.
- `useThreatIntelStream` opens `/api/v1/threat-intel/stream` SSE (mocked via `MockThreatIntelEventSource` in dev) and pushes events into `useThreatIntelEventStore`.

### Widget requirements

| Widget | Fields Needed | Notes |
| --- | --- | --- |
| IOC lookup banner | `lookupIndicator` response: `job_ids`, `cached`, `verdicts[].source/classification/confidence/retrieved_at` | Shows "cached" vs "queued", lists job IDs when returned. |
| IOC verdict cards | `fetchIndicator` payload: `verdicts[]` grouped by `source`, needs `classification`, `confidence`, `retrieved_at`. |
| Sample progress list | SSE events: `event`, `indicator`, `sample_id`, `source`, `status`, `classification`, `timestamp`; derived job statuses map by `source`. |
| Sample detail table | `fetchSample` response: `id`, `status`, `hash`, `filename`, `size`, `artifact_ids`, `task_run_id`, `agent_id`, `metadata`, `jobs[].source/status/attempt/error/artifact_ids/next_run_at/updated_at`. |
| Event feed | SSE events for the last 25 entries (fields above plus `message`). |
| Audit log | `/audit/events` returns `items[]` with `timestamp`, `actor`, `action`, `resource`. |

### Filters & pagination

- IOC lookup form lets users choose `kind`, multi-select `sources`, and `force` server scans. These parameters map 1:1 to backend `lookupRequestBody`.
- Sample detail panel is opened per `selectedSampleId`; there is no pagination—frontend slices `sampleSummaries` to 5 entries and event feed to 25 entries.
- Audit log fetch uses `limit=25` but no cursor, so repeated polling may miss older records; backend should expose cursor-based pagination for consistent auditing.

### Server snapshot

- `ThreatIntelHandler` exposes `POST /threat-intel/lookup`, `GET /threat-intel/iocs/:indicator`, `GET /threat-intel/samples/:id`, and `GET /threat-intel/jobs` (`server/internal/api/v1/threatintel.go`). Responses already contain `artifact_ids`, `source`, `status`, `attempt`, `updated_at` plus metadata.
- SSE hub (`server/internal/threatintel/events.go`, `types.go`) broadcasts events with JSON fields `{event, sample_id, job_id, indicator, source, status, classification, confidence, message, metadata, timestamp}`.

### Gaps

- `/threat-intel/jobs` returns `{jobs: [...]}` but the frontend never consumes it; instead it relies on SSE aggregation. We still need filters (`sample_id`, `status`, pagination) to hydrate job tables without waiting for SSE.
- SSE currently lacks explicit error codes or retry hints; UI expects to show connection pills and "reconnect" prompts.
- Audit log endpoint already filters by `action`, but there is no `threat-intel` specific namespace; we need to ensure actions follow `threatintel.*` so filtering works server-side.
- Sample detail lacks `classification`/`source` echo on the root object, so the UI leans on SSE to show verdict badges next to each sample.

## Task 1.2: Unified task list response & saved views API

To unlock server–frontend alignment we need a precise contract for `GET /api/v1/tasks` and a persistent `/api/v1/task-views` CRUD interface. This section defines the schema, filtering semantics, and frontend migration plan.

### `GET /api/v1/tasks` request parameters

| Param | Type | Notes |
| --- | --- | --- |
| `status` | comma-delimited string (`pending,running,failed`) | Accepts any combination of valid `TaskStatus`. Empty → all. Alias `running` should expand to `running,leased`. |
| `search` | string | Case-insensitive match across `task.id`, `task.type`, `metadata.targets`, `metadata.scenario_*`, `created_by`. Use `ILIKE` with `%keyword%`. |
| `type` | multi-value (comma) | Filter by task types. |
| `priority` | `min,max` pair (`priority_min`, `priority_max`) | Optional numeric bounds. |
| `owner` | string | Filter by `created_by`. |
| `date_from`, `date_to` | RFC3339 timestamps | Filter by `updated_at` range. |
| `limit` | int (default 50, max 200) | Page size; server echoes as `page_size`. |
| `cursor` | opaque string | Encodes `{updated_at, id}`. Absent → newest page. Cursor is base64 JSON: `{"updated_at":"...","id":"uuid"}`. |
| `sort` | enum (`updated_at_desc`, `updated_at_asc`, `priority_desc`) | Default `updated_at_desc`. Cursor respects sort order. |
| `view_id` | optional UUID | When present, server fetches stored filters and merges with explicit query params (explicit params override view settings). |

### Response envelope

```json
{
  "data": [Task, ...],
  "page_size": 50,
  "next_cursor": "eyJ1cGRhdGVkX2F0IjoiMjAyNC0xMi0xNFQxMjowMDowMFoiLCJpZCI6ImJiYy0xMjMifQ==",
  "filters": {
    "status": ["running", "failed"],
    "search": "acme",
    "type": ["respond"],
    "priority": {"min": 1, "max": 5},
    "date_range": {"from": "2024-12-01T00:00:00Z", "to": "2024-12-14T23:59:59Z"},
    "owner": "ops.lead",
    "view_id": "2d2e..."
  },
  "summary": {
    "total": 132,
    "by_status": {"pending": 10, "running": 22, "failed": 8, "succeeded": 92}
  }
}
```

- `next_cursor` is omitted when there is no subsequent page.
- `summary.total` counts rows that match the filter (up to 5k for performance). `by_status` is optional but allows the dashboard counters to avoid recomputation.
- `filters` echoes the normalized filter set after merging saved views + query params, allowing the frontend to sync state even after refresh.

### Pagination & cursor algorithm

1. Order tasks by the selected sort column (default `updated_at DESC, id DESC`).
2. Cursor contains the last row's sort keys. For `DESC`, fetch `WHERE (updated_at, id) < (cursor.updated_at, cursor.id)`; for `ASC`, use `>` comparisons.
3. Limit is inclusive of the row that produces the cursor; if fewer rows than `limit`, no cursor returned.
4. Cursors are opaque to clients; any tampering results in `400 invalid cursor`.

### `/api/v1/task-views` contract

| Endpoint | Description |
| --- | --- |
| `GET /api/v1/task-views` | Returns `{views: TaskView[]}` sorted by `updated_at DESC`. Supports optional `?include_shared=true` if we later add org-level views. |
| `POST /api/v1/task-views` | Body: `{name: string, filters: TaskFiltersInput, page_size?: number, is_default?: boolean}`. Stores under current user (`security.Principal`). Response: created `TaskView`. |
| `PUT /api/v1/task-views/:id` | Same payload as POST; only owner/admin may update. |
| `DELETE /api/v1/task-views/:id` | Soft-delete (mark `deleted_at`), returns `204`. |

`TaskView` model:

```json
{
  "id": "uuid",
  "name": "SLO 阈值观测",
  "owner": "ops.lead",
  "filters": { ... TaskFiltersInput ... },
  "page_size": 50,
  "is_default": false,
  "created_at": "2024-12-14T12:00:00Z",
  "updated_at": "2024-12-14T12:34:56Z"
}
```

`TaskFiltersInput` matches the request filter schema (status array, type array, search string, priority range, metadata tags, sort). Validation rules:

- Require at least one discriminator (`status`/`search`/`type`).
- Enforce `page_size` bounds (10–200).
- Serialize filters as JSONB column `filters`.

### Backend implementation notes

- Add `TaskView` table + `store` interface (`CreateTaskView`, `ListTaskViews`, `UpdateTaskView`, `DeleteTaskView`).
- Update `TaskHandler.listTasks` to:
  - Parse `view_id`, load saved view filters, merge with query params.
  - Build DB query with `WHERE` clauses for each filter.
  - Return envelope per schema.
- Provide `taskViewsHandler` under `/api/v1/task-views` with RBAC scopes `tasks.views.*`.
- Extend `TaskListResponseSchema` (frontend) and `TaskListResponse` type to reflect new structure.

### Frontend alignment plan

1. **Services layer**
   - Update `frontend/src/services/api/tasks.ts` to accept `TaskListQuery` and parse the new envelope (`TaskListResponseSchema = z.object({ data, page_size, next_cursor, filters, summary })`).
   - Add `taskViews.ts` service with `listTaskViews`, `createTaskView`, `updateTaskView`, `deleteTaskView`.
2. **Hooks**
   - `useTasksData` should send `filters` + `cursor`, expose `tasks`, `pageSize`, `nextCursor`, `filters`, `summary`, and `loadMore()` for infinite scroll or manual pagination.
   - `useTaskFilters` no longer writes to `localStorage`. Instead:
     - On mount, fetch `/task-views` and populate `views` state.
     - Persist ad-hoc filters via `applyView`, `saveCurrentView` -> POST to API.
     - Keep a lightweight local cache only when API fails (feature flag `VITE_ENABLE_TASK_VIEWS_API` fallback).
3. **UI changes**
   - `TaskFilters` should show server-provided view list; deleting a view calls API.
   - `TaskList` receives pagination props: show `Load more` when `next_cursor` exists; update `page_size`.
   - `TaskBoard` consumes `summary.by_status`.
   - `TaskLiveMonitor` still uses SSE but can display `filters.view_id` to indicate active saved view.
4. **Migration**
   - On first load post-upgrade: read legacy `localStorage` entries, POST them as saved views (best-effort), then remove the local keys.
   - Provide toast/warning when API unavailable and fallback to local views.

## Task 1.3: Threat Intel REST ↔ SSE contract

The Threat Intel workspace stitches together multiple resources: indicator lookups, uploaded samples/artifacts, and provider jobs. Currently, REST endpoints (`/lookup`, `/iocs`, `/samples`, `/jobs`) and SSE events expose overlapping but inconsistent fields. This section specifies the authoritative mapping and required field/error semantics.

### Data flow overview

1. **Indicator lookup**: `POST /api/v1/threat-intel/lookup` enqueues provider jobs (MetaDefender, OpenTIP) and may return cached verdicts immediately.
2. **Sample ingestion**: Artifact uploads (from responders or automated flows) call orchestrator `SubmitSample`, which creates a `ThreatIntelSample` record and jobs for each provider.
3. **Job execution**: Workers lease jobs, interact with providers, and persist verdicts/artifacts.
4. **SSE stream**: `/api/v1/threat-intel/stream` broadcasts lifecycle events so the UI can render progress cards in real time.
5. **REST polling**: `GET /threat-intel/iocs/{indicator}` and `GET /threat-intel/samples/{id}` provide ground truth for verdict summaries and job history; `/threat-intel/jobs` exposes the queue backlog for debugging.

### REST contract requirements

| Endpoint | Required fields | Notes |
| --- | --- | --- |
| `POST /threat-intel/lookup` | `job_ids[]`, `cached`, `verdicts[]`, `error_code?`, `message?` | On success, HTTP 202 with job IDs. On cache hit, HTTP 200 + `cached=true`. On failure, HTTP 503/429 with `error_code`. |
| `GET /threat-intel/iocs/{indicator}` | `indicator`, `kind`, `verdict_summaries[]` (per source), `samples[]` (recent sample IDs, status, artifact_ids), `last_error?` | `verdict_summaries` should include `classification`, `confidence`, `retrieved_at`, `expires_at`, `provider_metadata`. |
| `GET /threat-intel/samples/{id}` | Existing fields + `indicator`, `classification`, `source`, `artifact_details[]`, `job_statuses` map, `last_error_code?` | `artifact_details` includes `{id, sha256, mime_type, quarantine_path}` for UI download links. |
| `GET /threat-intel/jobs?sample_id=` | Queryable by `sample_id`, `indicator`, `status`, `source`, `cursor`. Response envelope: `{data: jobs[], next_cursor, summary}` similar to tasks API. Each job reports `artifact_ids`, `status`, `attempt`, `error_code`, `last_error`, `last_transition_at`. |

Missing fields to add/doct:
- Samples currently omit `indicator`, `classification`, and aggregated `job_statuses`; these must be derived server-side so UI doesn’t rely on SSE inference.
- Job records need `artifact_ids` + `source_status` detail to show which provider failed.
- `/lookup` errors should include machine-readable codes (see below).

### SSE event schema

Each event emitted by `threatintel.Hub` MUST include:

```json
{
  "event": "lookup_queued | job_running | job_failed | job_succeeded | sample_completed | sample_failed | verdict_ready | artifact_uploaded",
  "indicator": "sha256:...",
  "sample_id": "uuid?",
  "job_id": "uuid?",
  "source": "opentip|metadefender",
  "status": "pending|running|succeeded|failed|retrying|completed|scanning",
  "classification": "malicious|suspicious|benign|unknown",
  "confidence": "high|medium|low",
  "artifact_ids": ["uuid", "..."],
  "artifact_types": ["pe", "url"],
  "error_code": "TI_PROVIDER_TIMEOUT?",
  "message": "human readable",
  "metadata": {
    "task_run_id": "uuid",
    "agent_id": "uuid",
    "filename": "sample.exe",
    "mime_type": "application/x-dosexec"
  },
  "timestamp": "RFC3339"
}
```

Event-to-REST linkage:

| Event | REST resource to refresh | Trigger |
| --- | --- | --- |
| `lookup_queued` | none (UI shows queued badge) | Immediately after `/lookup` enqueues jobs |
| `job_running` | `/threat-intel/samples/{sample_id}`, `/threat-intel/jobs?sample_id=` | Worker leases job |
| `job_succeeded` / `job_failed` | Same as above | Worker completes job |
| `sample_completed` / `sample_failed` | `/threat-intel/samples/{id}` | All jobs done |
| `verdict_ready` | `/threat-intel/iocs/{indicator}` | New verdict persisted |
| `artifact_uploaded` | `/threat-intel/samples/{id}` | Artifact ingestion finished |

The UI should be able to render cards using SSE alone, but REST remains source of truth. Therefore, SSE payloads must stay consistent with REST fields (`classification`, `artifact_ids`, etc.).

### Error code taxonomy

Define shared error codes (REST + SSE `error_code`) to simplify UI messaging:

| Code | Meaning | HTTP status | Surfaces in |
| --- | --- | --- | --- |
| `TI_NOT_ENABLED` | Threat Intel orchestrator disabled | 503 | `/lookup` |
| `TI_RATE_LIMITED` | External provider throttled | 429 | `/lookup`, job events |
| `TI_PROVIDER_TIMEOUT` | Provider request timed out | 504 | job events |
| `TI_PROVIDER_ERROR` | Provider returned error payload | 502 | job events |
| `TI_SAMPLE_NOT_FOUND` | Sample ID invalid/expired | 404 | `/samples/:id` |
| `TI_ARTIFACT_UPLOAD_FAILED` | Artifact storage error | 500 | SSE event + `/samples/:id` |
| `TI_JOB_RETRYING` | Job entered retry backoff | 202 | job events |

Implementation requirements:

- Update orchestrator error handling (`handleJobError`, `failJob`) to map Go errors to these codes and propagate to both REST responses (where applicable) and SSE events.
- Store last error code on samples/jobs (`last_error_code` column) so REST responses can show it and UI can match SSE notifications.

### Frontend implications

- `useThreatIntelStream` should parse `artifact_ids`, `artifact_types`, `error_code`. Extend `ThreatIntelEventSchema` accordingly.
- `ThreatIntelWorkspace` sample list should use server-provided `classification`/`job_statuses` instead of reconstructing from SSE. SSE becomes incremental updates that merge into store state keyed by `sample_id`.
- When `error_code` indicates provider issues, show actionable hints (retry, docs link).
- Add job table view referencing `/threat-intel/jobs` so analysts can inspect stuck providers without relying on SSE history.

### Backend gaps summary

1. `ThreatIntelHandler` must enrich `/iocs`, `/samples`, `/jobs` responses with fields listed above.
2. Store layer needs schema changes for `samples.indicator`, `samples.artifact_details`, `samples.last_error_code`, `jobs.error_code`.
3. SSE events must include `artifact_ids`, `classification`, `confidence`, `error_code`, and consistent event names.
4. Standardize error codes in orchestrator and REST handlers.
