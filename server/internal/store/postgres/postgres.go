package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/m-sec-org/d-eyes/server/internal/config"
	"github.com/m-sec-org/d-eyes/server/internal/model"
	"github.com/m-sec-org/d-eyes/server/internal/store"
)

type PostgresStore struct {
	pool *pgxpool.Pool
}

type eventFilterBuilder struct {
	clauses []string
	args    []any
	next    int
}

func newEventFilterBuilder() *eventFilterBuilder {
	return &eventFilterBuilder{next: 1}
}

func (b *eventFilterBuilder) add(expr string, value any) {
	b.clauses = append(b.clauses, fmt.Sprintf(expr, b.next))
	b.args = append(b.args, value)
	b.next++
}

func (b *eventFilterBuilder) addIn(expr string, values []string) {
	placeholders := make([]string, len(values))
	for i, v := range values {
		placeholders[i] = fmt.Sprintf("$%d", b.next)
		b.args = append(b.args, v)
		b.next++
	}
	b.clauses = append(b.clauses, fmt.Sprintf("%s IN (%s)", expr, strings.Join(placeholders, ",")))
}

func (b *eventFilterBuilder) sql() (string, []any) {
	if len(b.clauses) == 0 {
		return "", b.args
	}
	return " WHERE " + strings.Join(b.clauses, " AND "), b.args
}

func buildEventFilters(query store.SystemEventQuery, includeCursor bool) *eventFilterBuilder {
	b := newEventFilterBuilder()
	collector := strings.ToLower(strings.TrimSpace(query.Collector))
	collectorKind := strings.ToLower(strings.TrimSpace(query.CollectorKind))
	eventType := strings.ToLower(strings.TrimSpace(query.EventType))
	source := strings.ToLower(strings.TrimSpace(query.Source))
	priorities := store.NormalizeStringList(query.Priorities)
	tiers := store.NormalizeStringList(query.StorageTiers)
	if query.AgentID != uuid.Nil {
		b.add("agent_id=$%d", query.AgentID)
	}
	if collector != "" {
		b.add("LOWER(collector)=$%d", collector)
	}
	if collectorKind != "" {
		b.add("LOWER(collector_kind)=$%d", collectorKind)
	}
	if eventType != "" {
		b.add("LOWER(event_type)=$%d", eventType)
	}
	if source != "" {
		b.add("LOWER(source)=$%d", source)
	}
	if len(priorities) > 0 {
		b.addIn("LOWER(COALESCE(priority,'normal'))", priorities)
	}
	if len(tiers) > 0 {
		b.addIn("LOWER(COALESCE(storage_tier,'hot'))", tiers)
	}
	if !query.Since.IsZero() {
		b.add("received_at >= $%d", query.Since)
	}
	if !query.Until.IsZero() {
		b.add("received_at <= $%d", query.Until)
	}
	if includeCursor && !query.CursorReceivedAt.IsZero() {
		if query.SortAscending {
			b.clauses = append(b.clauses, fmt.Sprintf("(received_at > $%d OR (received_at = $%d AND id > $%d))", b.next, b.next, b.next+1))
			b.args = append(b.args, query.CursorReceivedAt, query.CursorReceivedAt, query.CursorID)
			b.next += 3
		} else {
			b.clauses = append(b.clauses, fmt.Sprintf("(received_at < $%d OR (received_at = $%d AND id < $%d))", b.next, b.next, b.next+1))
			b.args = append(b.args, query.CursorReceivedAt, query.CursorReceivedAt, query.CursorID)
			b.next += 3
		}
	}
	return b
}

func New(ctx context.Context, cfg config.DatabaseConfig) (*PostgresStore, error) {
	pool, err := pgxpool.New(ctx, cfg.DSN)
	if err != nil {
		return nil, fmt.Errorf("connect postgres: %w", err)
	}
	if cfg.MaxOpenConns > 0 {
		pool.Config().MaxConns = int32(cfg.MaxOpenConns)
	}
	st := &PostgresStore{pool: pool}
	if err := st.ensureSchema(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	if err := st.runMigrations(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return st, nil
}

func (p *PostgresStore) ensureSchema(ctx context.Context) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS agents (
            id UUID PRIMARY KEY,
            name TEXT,
            labels JSONB,
            platform TEXT,
            version TEXT,
            capabilities JSONB,
            status TEXT NOT NULL DEFAULT 'offline',
            last_heartbeat TIMESTAMPTZ,
            load DOUBLE PRECISION DEFAULT 0,
            running_tasks TEXT[] DEFAULT '{}'::text[],
            metadata JSONB,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )`,
		`CREATE UNIQUE INDEX IF NOT EXISTS agents_name_idx ON agents (name)`,
		`ALTER TABLE agents ADD COLUMN IF NOT EXISTS load DOUBLE PRECISION DEFAULT 0`,
		`ALTER TABLE agents ADD COLUMN IF NOT EXISTS running_tasks TEXT[] DEFAULT '{}'::text[]`,
		`ALTER TABLE agents ADD COLUMN IF NOT EXISTS metadata JSONB`,
		`CREATE TABLE IF NOT EXISTS tasks (
            id UUID PRIMARY KEY,
            type TEXT NOT NULL,
            profile TEXT,
            priority INT NOT NULL,
            payload JSONB,
            status TEXT NOT NULL,
            retry_count INT NOT NULL DEFAULT 0,
            metadata JSONB,
            created_by TEXT,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )`,
		`CREATE TABLE IF NOT EXISTS task_runs (
            id UUID PRIMARY KEY,
            task_id UUID NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
            task_type TEXT NOT NULL,
            agent_id UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
            lease_id UUID UNIQUE NOT NULL,
            lease_expires TIMESTAMPTZ NOT NULL,
            started_at TIMESTAMPTZ,
            finished_at TIMESTAMPTZ,
            status TEXT NOT NULL,
            error_message TEXT,
            summary JSONB,
            result_metadata JSONB,
            exit_code INT,
            error_code TEXT,
            expires_at TIMESTAMPTZ,
            retry_sequence INT NOT NULL DEFAULT 0
        )`,
		`CREATE TABLE IF NOT EXISTS artifacts (
            id UUID PRIMARY KEY,
            task_run_id UUID NOT NULL REFERENCES task_runs(id) ON DELETE CASCADE,
            name TEXT NOT NULL,
            mime_type TEXT,
            blob BYTEA
        )`,
		`CREATE TABLE IF NOT EXISTS task_results (
            id UUID PRIMARY KEY,
            task_id UUID NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
            task_type TEXT NOT NULL,
            profile TEXT,
            run_id UUID NOT NULL REFERENCES task_runs(id) ON DELETE CASCADE,
            agent_id UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
            status TEXT NOT NULL,
            metadata JSONB,
            summary JSONB,
            error_message TEXT,
            exit_code INT,
            error_code TEXT,
            scenario_id TEXT,
            scenario_name TEXT,
            completed_at TIMESTAMPTZ NOT NULL,
            created_at TIMESTAMPTZ NOT NULL
        )`,
		`CREATE TABLE IF NOT EXISTS threat_intel_samples (
            id UUID PRIMARY KEY,
            indicator TEXT,
            hash TEXT NOT NULL,
            filename TEXT,
            size BIGINT,
            status TEXT NOT NULL,
            artifact_ids UUID[] DEFAULT '{}'::uuid[],
            artifact_details JSONB DEFAULT '{}'::jsonb,
            task_run_id UUID NOT NULL REFERENCES task_runs(id) ON DELETE CASCADE,
            agent_id UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
            source TEXT,
            classification TEXT,
            metadata JSONB DEFAULT '{}'::jsonb,
            last_error TEXT,
            last_error_code TEXT,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )`,
		`CREATE INDEX IF NOT EXISTS threat_intel_samples_hash_idx ON threat_intel_samples(hash)`,
		`CREATE TABLE IF NOT EXISTS threat_intel_jobs (
            id UUID PRIMARY KEY,
            sample_id UUID REFERENCES threat_intel_samples(id) ON DELETE CASCADE,
            indicator TEXT,
            kind TEXT,
            source TEXT,
            status TEXT NOT NULL,
            payload BYTEA,
            attempt INT NOT NULL DEFAULT 0,
            error_msg TEXT,
            error_code TEXT,
            next_run_at TIMESTAMPTZ,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            last_transition_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            task_run_id UUID REFERENCES task_runs(id) ON DELETE CASCADE,
            agent_id UUID REFERENCES agents(id) ON DELETE CASCADE,
            artifact_ids UUID[] DEFAULT '{}'::uuid[],
            metadata JSONB DEFAULT '{}'::jsonb,
            summary JSONB DEFAULT '{}'::jsonb
        )`,
		`CREATE INDEX IF NOT EXISTS threat_intel_jobs_status_idx ON threat_intel_jobs(status, next_run_at)`,
		`CREATE INDEX IF NOT EXISTS threat_intel_jobs_indicator_idx ON threat_intel_jobs(indicator)`,
		`CREATE TABLE IF NOT EXISTS threat_intel_verdicts (
            id UUID PRIMARY KEY,
            indicator TEXT NOT NULL,
            kind TEXT,
            source TEXT,
            classification TEXT,
            confidence TEXT,
            raw JSONB,
            retrieved_at TIMESTAMPTZ NOT NULL,
            expires_at TIMESTAMPTZ,
            job_id UUID REFERENCES threat_intel_jobs(id) ON DELETE CASCADE,
            task_run_id UUID REFERENCES task_runs(id) ON DELETE CASCADE,
            metadata JSONB DEFAULT '{}'::jsonb,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )`,
		`CREATE INDEX IF NOT EXISTS threat_intel_verdicts_indicator_idx ON threat_intel_verdicts(indicator)`,
		`CREATE TABLE IF NOT EXISTS behavior_metrics (
		    id UUID PRIMARY KEY,
		    agent_id UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
		    load DOUBLE PRECISION,
		    cpu_percent DOUBLE PRECISION,
		    latency_ms DOUBLE PRECISION,
		    running_tasks TEXT[],
		    blocked_actions TEXT[],
		    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`,
		`CREATE INDEX IF NOT EXISTS behavior_metrics_agent_idx ON behavior_metrics(agent_id, created_at DESC)`,
		`CREATE TABLE IF NOT EXISTS behavior_events (
		    id UUID PRIMARY KEY,
		    agent_id UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
		    task_id UUID REFERENCES tasks(id) ON DELETE CASCADE,
		    metadata JSONB,
		    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`,
		`CREATE INDEX IF NOT EXISTS behavior_events_agent_idx ON behavior_events(agent_id, created_at DESC)`,
		`CREATE TABLE IF NOT EXISTS system_events (
		    id UUID PRIMARY KEY,
		    agent_id UUID REFERENCES agents(id) ON DELETE SET NULL,
		    agent_name TEXT,
		    collector TEXT,
		    collector_kind TEXT,
		    event_type TEXT NOT NULL,
		    source TEXT,
		    priority TEXT,
		    storage_tier TEXT,
		    event_timestamp TIMESTAMPTZ NOT NULL,
		    sequence BIGINT,
		    payload JSONB,
		    metadata JSONB,
		    tags JSONB,
		    raw JSONB,
		    received_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`,
		`CREATE INDEX IF NOT EXISTS system_events_agent_idx ON system_events(agent_id, received_at DESC)`,
		`CREATE INDEX IF NOT EXISTS system_events_type_idx ON system_events(event_type, received_at DESC)`,
		`ALTER TABLE system_events ADD COLUMN IF NOT EXISTS priority TEXT`,
		`ALTER TABLE system_events ADD COLUMN IF NOT EXISTS storage_tier TEXT`,
		`CREATE TABLE IF NOT EXISTS collector_configs (
		    agent_id UUID PRIMARY KEY REFERENCES agents(id) ON DELETE CASCADE,
		    version BIGINT NOT NULL,
		    config JSONB NOT NULL,
		    updated_by TEXT,
		    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`,
		`CREATE TABLE IF NOT EXISTS collector_statuses (
		    agent_id UUID PRIMARY KEY REFERENCES agents(id) ON DELETE CASCADE,
		    agent_name TEXT,
		    version BIGINT,
		    state TEXT,
		    last_error TEXT,
		    stats JSONB,
		    metadata JSONB,
		    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`,
		`CREATE TABLE IF NOT EXISTS collector_rollouts (
		    id UUID PRIMARY KEY,
		    name TEXT,
		    description TEXT,
		    selector JSONB,
		    status TEXT NOT NULL,
		    config JSONB NOT NULL,
		    version BIGINT,
		    strategy TEXT,
		    created_by TEXT,
		    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		    completed_at TIMESTAMPTZ,
		    rolled_back_at TIMESTAMPTZ,
		    rollback_reason TEXT,
		    grace_period_seconds BIGINT,
		    target_count INT NOT NULL DEFAULT 0,
		    ack_count INT NOT NULL DEFAULT 0,
		    failed_count INT NOT NULL DEFAULT 0,
		    notes TEXT
		)`,
		`CREATE TABLE IF NOT EXISTS collector_rollout_targets (
		    rollout_id UUID NOT NULL REFERENCES collector_rollouts(id) ON DELETE CASCADE,
		    agent_id UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
		    agent_name TEXT,
		    desired_version BIGINT,
		    previous_version BIGINT,
		    previous_config JSONB,
		    state TEXT NOT NULL,
		    acked_at TIMESTAMPTZ,
		    last_heartbeat TIMESTAMPTZ,
		    last_error TEXT,
		    metadata JSONB,
		    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		    PRIMARY KEY (rollout_id, agent_id)
		)`,
		`CREATE INDEX IF NOT EXISTS collector_rollout_targets_agent_idx ON collector_rollout_targets(agent_id)`,
		`CREATE TABLE IF NOT EXISTS anomalies (
		    id UUID PRIMARY KEY,
		    agent_id UUID REFERENCES agents(id) ON DELETE CASCADE,
		    task_id UUID REFERENCES tasks(id) ON DELETE SET NULL,
		    ioc TEXT,
		    entities JSONB,
		    severity TEXT,
		    score DOUBLE PRECISION,
		    summary JSONB,
		    status TEXT,
		    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`,
		`ALTER TABLE anomalies ADD COLUMN IF NOT EXISTS task_id UUID REFERENCES tasks(id) ON DELETE SET NULL`,
		`ALTER TABLE anomalies ADD COLUMN IF NOT EXISTS ioc TEXT`,
		`ALTER TABLE anomalies ADD COLUMN IF NOT EXISTS entities JSONB`,
		`CREATE INDEX IF NOT EXISTS anomalies_agent_idx ON anomalies(agent_id, created_at DESC)`,
	}
	for _, stmt := range stmts {
		if _, err := p.pool.Exec(ctx, stmt); err != nil {
			return fmt.Errorf("ensure schema: %w", err)
		}
	}
	return nil
}

func (p *PostgresStore) close() {
	p.pool.Close()
}

func (p *PostgresStore) UpsertAgent(ctx context.Context, agent *model.Agent) error {
	if agent.ID == uuid.Nil {
		agent.ID = uuid.New()
	}
	now := time.Now()
	labelsJSON, _ := json.Marshal(agent.Labels)
	capsJSON, _ := json.Marshal(agent.Capabilities)
	metadataJSON, _ := json.Marshal(agent.Metadata)
	_, err := p.pool.Exec(ctx, `INSERT INTO agents (id, name, labels, platform, version, capabilities, status, last_heartbeat, load, running_tasks, metadata, created_at, updated_at)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
        ON CONFLICT (id) DO UPDATE SET
            name = EXCLUDED.name,
            labels = EXCLUDED.labels,
            platform = EXCLUDED.platform,
            version = EXCLUDED.version,
            capabilities = EXCLUDED.capabilities,
            status = EXCLUDED.status,
            last_heartbeat = EXCLUDED.last_heartbeat,
            updated_at = EXCLUDED.updated_at`,
		agent.ID, agent.Name, labelsJSON, agent.Platform, agent.Version, capsJSON, agent.Status, agent.LastHeartbeat, agent.Load, agent.RunningTasks, metadataJSON, now, now)
	if err != nil {
		return fmt.Errorf("upsert agent: %w", err)
	}
	return nil
}

func (p *PostgresStore) GetAgentByName(ctx context.Context, name string) (*model.Agent, error) {
	row := p.pool.QueryRow(ctx, `SELECT id, name, labels, platform, version, capabilities, status, last_heartbeat, load, running_tasks, metadata, created_at, updated_at FROM agents WHERE name = $1`, name)
	return scanAgent(row)
}

func (p *PostgresStore) GetAgent(ctx context.Context, id uuid.UUID) (*model.Agent, error) {
	row := p.pool.QueryRow(ctx, `SELECT id, name, labels, platform, version, capabilities, status, last_heartbeat, load, running_tasks, metadata, created_at, updated_at FROM agents WHERE id = $1`, id)
	return scanAgent(row)
}

func (p *PostgresStore) UpdateAgentStatus(ctx context.Context, id uuid.UUID, status model.AgentStatus, heartbeat time.Time, load float64, running []string, metadata map[string]string) error {
	metadataJSON, _ := json.Marshal(metadata)
	_, err := p.pool.Exec(ctx, `UPDATE agents SET status=$2, last_heartbeat=$3, load=$4, running_tasks=$5, metadata=$6, updated_at=NOW() WHERE id=$1`,
		id, status, heartbeat, load, running, metadataJSON)
	if err != nil {
		return fmt.Errorf("update agent status: %w", err)
	}
	return nil
}

func (p *PostgresStore) UpdateAgentMetadata(ctx context.Context, id uuid.UUID, labels map[string]string) error {
	labelsJSON, _ := json.Marshal(labels)
	_, err := p.pool.Exec(ctx, `UPDATE agents SET labels=$2, updated_at=NOW() WHERE id=$1`, id, labelsJSON)
	if err != nil {
		return fmt.Errorf("update agent metadata: %w", err)
	}
	return nil
}

func (p *PostgresStore) CreateTask(ctx context.Context, task *model.Task) error {
	if task.ID == uuid.Nil {
		task.ID = uuid.New()
	}
	now := time.Now()
	metadataJSON, _ := json.Marshal(task.Metadata)
	payloadJSON := json.RawMessage(task.Payload)
	_, err := p.pool.Exec(ctx, `INSERT INTO tasks (id, type, profile, priority, payload, status, retry_count, metadata, created_by, created_at, updated_at)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
		task.ID, string(task.Type), task.Profile, task.Priority, payloadJSON, string(task.Status), task.RetryCount, metadataJSON, task.CreatedBy, now, now)
	if err != nil {
		return fmt.Errorf("create task: %w", err)
	}
	return nil
}

func (p *PostgresStore) UpdateTaskStatus(ctx context.Context, taskID uuid.UUID, status model.TaskStatus) error {
	_, err := p.pool.Exec(ctx, `UPDATE tasks SET status=$2, updated_at=NOW() WHERE id=$1`, taskID, string(status))
	if err != nil {
		return fmt.Errorf("update task status: %w", err)
	}
	return nil
}

func (p *PostgresStore) IncrementTaskRetry(ctx context.Context, taskID uuid.UUID) error {
	_, err := p.pool.Exec(ctx, `UPDATE tasks SET retry_count = retry_count + 1, updated_at=NOW() WHERE id=$1`, taskID)
	if err != nil {
		return fmt.Errorf("increment retry: %w", err)
	}
	return nil
}

func (p *PostgresStore) GetTask(ctx context.Context, id uuid.UUID) (*model.Task, error) {
	row := p.pool.QueryRow(ctx, `SELECT id, type, profile, priority, payload, status, retry_count, metadata, created_by, created_at, updated_at FROM tasks WHERE id=$1`, id)
	var task model.Task
	var payload []byte
	var metadata []byte
	if err := row.Scan(&task.ID, &task.Type, &task.Profile, &task.Priority, &payload, &task.Status, &task.RetryCount, &metadata, &task.CreatedBy, &task.CreatedAt, &task.UpdatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, store.ErrNotFound
		}
		return nil, fmt.Errorf("scan task: %w", err)
	}
	task.Payload = append([]byte(nil), payload...)
	if len(metadata) > 0 {
		_ = json.Unmarshal(metadata, &task.Metadata)
	}
	return &task, nil
}

func (p *PostgresStore) ListPendingTasks(ctx context.Context, limit int) ([]*model.Task, error) {
	rows, err := p.pool.Query(ctx, `SELECT id, type, profile, priority, payload, status, retry_count, metadata, created_by, created_at, updated_at FROM tasks WHERE status='pending' ORDER BY priority ASC, created_at ASC LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("list pending tasks: %w", err)
	}
	defer rows.Close()
	var res []*model.Task
	for rows.Next() {
		var task model.Task
		var payload []byte
		var metadata []byte
		if err := rows.Scan(&task.ID, &task.Type, &task.Profile, &task.Priority, &payload, &task.Status, &task.RetryCount, &metadata, &task.CreatedBy, &task.CreatedAt, &task.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan pending task: %w", err)
		}
		task.Payload = append([]byte(nil), payload...)
		if len(metadata) > 0 {
			_ = json.Unmarshal(metadata, &task.Metadata)
		}
		res = append(res, &task)
	}
	return res, nil
}

func (p *PostgresStore) ListTasks(ctx context.Context, opts store.ListTasksOptions) (store.ListTasksResult, error) {
	limit := clampTaskListLimit(opts.Limit)
	whereClause, args := buildTaskFilterClause(opts, true)
	fetchLimit := limit + 1
	args = append(args, fetchLimit)
	query := fmt.Sprintf(`SELECT id, type, profile, priority, payload, status, retry_count, metadata, created_by, created_at, updated_at FROM tasks %s ORDER BY updated_at DESC, id DESC LIMIT $%d`, whereClause, len(args))
	rows, err := p.pool.Query(ctx, query, args...)
	if err != nil {
		return store.ListTasksResult{}, fmt.Errorf("list tasks: %w", err)
	}
	defer rows.Close()
	result := store.ListTasksResult{
		Summary: store.TaskListSummary{
			ByStatus: make(map[model.TaskStatus]int64),
		},
	}
	for rows.Next() {
		var task model.Task
		var payload []byte
		var metadata []byte
		if err := rows.Scan(&task.ID, &task.Type, &task.Profile, &task.Priority, &payload, &task.Status, &task.RetryCount, &metadata, &task.CreatedBy, &task.CreatedAt, &task.UpdatedAt); err != nil {
			return store.ListTasksResult{}, fmt.Errorf("scan task: %w", err)
		}
		task.Payload = append([]byte(nil), payload...)
		if len(metadata) > 0 {
			_ = json.Unmarshal(metadata, &task.Metadata)
		}
		result.Tasks = append(result.Tasks, &task)
	}
	if len(result.Tasks) > limit {
		tail := result.Tasks[limit]
		result.NextCursor = &store.TaskListCursor{
			ID:        tail.ID,
			UpdatedAt: tail.UpdatedAt,
		}
		result.Tasks = result.Tasks[:limit]
	}
	summary, err := p.computeTaskSummary(ctx, opts)
	if err != nil {
		return store.ListTasksResult{}, err
	}
	result.Summary = summary
	return result, nil
}

func clampTaskListLimit(limit int) int {
	const (
		defaultLimit = 50
		maxLimit     = 200
	)
	if limit <= 0 {
		return defaultLimit
	}
	if limit > maxLimit {
		return maxLimit
	}
	return limit
}

func (p *PostgresStore) computeTaskSummary(ctx context.Context, opts store.ListTasksOptions) (store.TaskListSummary, error) {
	summary := store.TaskListSummary{
		ByStatus: make(map[model.TaskStatus]int64),
	}
	whereClause, args := buildTaskFilterClause(opts, false)
	query := fmt.Sprintf(`SELECT status, COUNT(*) FROM tasks %s GROUP BY status`, whereClause)
	rows, err := p.pool.Query(ctx, query, args...)
	if err != nil {
		return summary, fmt.Errorf("task summary: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var status string
		var count int64
		if err := rows.Scan(&status, &count); err != nil {
			return summary, fmt.Errorf("scan task summary: %w", err)
		}
		st := model.TaskStatus(status)
		summary.ByStatus[st] = count
		summary.Total += count
	}
	return summary, nil
}

func buildTaskFilterClause(opts store.ListTasksOptions, includeCursor bool) (string, []interface{}) {
	var clauses []string
	args := make([]interface{}, 0, 4)
	idx := 1
	if len(opts.Statuses) > 0 {
		statusVals := make([]string, len(opts.Statuses))
		for i, st := range opts.Statuses {
			statusVals[i] = string(st)
		}
		clauses = append(clauses, fmt.Sprintf("status = ANY($%d)", idx))
		args = append(args, statusVals)
		idx++
	}
	if search := strings.TrimSpace(opts.Search); search != "" {
		clauses = append(clauses, fmt.Sprintf("(id::text ILIKE $%d OR type ILIKE $%d OR created_by ILIKE $%d OR metadata::text ILIKE $%d)", idx, idx, idx, idx))
		args = append(args, "%"+search+"%")
		idx++
	}
	if includeCursor && opts.Cursor != nil && opts.Cursor.ID != uuid.Nil {
		clauses = append(clauses, fmt.Sprintf("(updated_at < $%d OR (updated_at = $%d AND id < $%d))", idx, idx, idx+1))
		args = append(args, opts.Cursor.UpdatedAt)
		idx++
		args = append(args, opts.Cursor.ID)
		idx++
	}
	if len(clauses) == 0 {
		return "", args
	}
	return " WHERE " + strings.Join(clauses, " AND "), args
}

func (p *PostgresStore) CreateTaskView(ctx context.Context, view *model.TaskView) error {
	if view == nil {
		return fmt.Errorf("task view required")
	}
	if view.ID == uuid.Nil {
		view.ID = uuid.New()
	}
	now := time.Now().UTC()
	filters := view.Filters
	if filters == nil {
		filters = map[string]interface{}{}
	}
	filtersJSON, err := json.Marshal(filters)
	if err != nil {
		return fmt.Errorf("marshal filters: %w", err)
	}
	_, err = p.pool.Exec(ctx, `INSERT INTO task_views (id, name, owner, filters, page_size, is_default, created_at, updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		view.ID, view.Name, view.Owner, filtersJSON, view.PageSize, view.IsDefault, now, now)
	if err != nil {
		return fmt.Errorf("create task view: %w", err)
	}
	view.CreatedAt = now
	view.UpdatedAt = now
	return nil
}

func (p *PostgresStore) ListTaskViews(ctx context.Context, owner string) ([]*model.TaskView, error) {
	rows, err := p.pool.Query(ctx, `SELECT id, name, owner, filters, page_size, is_default, created_at, updated_at FROM task_views WHERE owner=$1 AND deleted_at IS NULL ORDER BY updated_at DESC`, owner)
	if err != nil {
		return nil, fmt.Errorf("list task views: %w", err)
	}
	defer rows.Close()
	var views []*model.TaskView
	for rows.Next() {
		view, err := scanTaskView(rows)
		if err != nil {
			return nil, err
		}
		views = append(views, view)
	}
	return views, nil
}

func (p *PostgresStore) UpdateTaskView(ctx context.Context, view *model.TaskView) error {
	if view == nil {
		return fmt.Errorf("task view required")
	}
	filters := view.Filters
	if filters == nil {
		filters = map[string]interface{}{}
	}
	filtersJSON, err := json.Marshal(filters)
	if err != nil {
		return fmt.Errorf("marshal filters: %w", err)
	}
	now := time.Now().UTC()
	tag, err := p.pool.Exec(ctx, `UPDATE task_views SET name=$1, filters=$2, page_size=$3, is_default=$4, updated_at=$5 WHERE id=$6 AND owner=$7 AND deleted_at IS NULL`,
		view.Name, filtersJSON, view.PageSize, view.IsDefault, now, view.ID, view.Owner)
	if err != nil {
		return fmt.Errorf("update task view: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return store.ErrNotFound
	}
	view.UpdatedAt = now
	return nil
}

func (p *PostgresStore) DeleteTaskView(ctx context.Context, id uuid.UUID, owner string) error {
	now := time.Now().UTC()
	tag, err := p.pool.Exec(ctx, `UPDATE task_views SET deleted_at=$1, updated_at=$1 WHERE id=$2 AND owner=$3 AND deleted_at IS NULL`, now, id, owner)
	if err != nil {
		return fmt.Errorf("delete task view: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return store.ErrNotFound
	}
	return nil
}

func scanTaskView(row pgx.Row) (*model.TaskView, error) {
	var (
		view       model.TaskView
		filtersRaw []byte
	)
	if err := row.Scan(&view.ID, &view.Name, &view.Owner, &filtersRaw, &view.PageSize, &view.IsDefault, &view.CreatedAt, &view.UpdatedAt); err != nil {
		return nil, fmt.Errorf("scan task view: %w", err)
	}
	if len(filtersRaw) > 0 {
		if err := json.Unmarshal(filtersRaw, &view.Filters); err != nil {
			return nil, fmt.Errorf("decode task view filters: %w", err)
		}
	} else {
		view.Filters = map[string]interface{}{}
	}
	return &view, nil
}

func (p *PostgresStore) ListAgents(ctx context.Context) ([]*model.Agent, error) {
	rows, err := p.pool.Query(ctx, `SELECT id, name, labels, platform, version, capabilities, status, last_heartbeat, load, running_tasks, metadata, created_at, updated_at FROM agents`)
	if err != nil {
		return nil, fmt.Errorf("list agents: %w", err)
	}
	defer rows.Close()

	var agents []*model.Agent
	for rows.Next() {
		agent, err := scanAgent(rows)
		if err != nil {
			return nil, err
		}
		agents = append(agents, agent)
	}
	return agents, nil
}

func (p *PostgresStore) CreateTaskRun(ctx context.Context, run *model.TaskRun) error {
	if run.ID == uuid.Nil {
		run.ID = uuid.New()
	}
	if run.LeaseID == uuid.Nil {
		run.LeaseID = uuid.New()
	}
	meta := run.Metadata
	if meta == nil {
		meta = map[string]string{}
	}
	metadataJSON, _ := json.Marshal(meta)
	_, err := p.pool.Exec(ctx, `INSERT INTO task_runs (id, task_id, task_type, agent_id, lease_id, lease_expires, started_at, finished_at, status, error_message, summary, result_metadata, exit_code, error_code, expires_at, retry_sequence)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)`,
		run.ID, run.TaskID, string(run.TaskType), run.AgentID, run.LeaseID, run.LeaseExpires, run.StartedAt, run.FinishedAt, string(run.Status), run.ErrorMessage, run.Summary, metadataJSON, run.ExitCode, run.ErrorCode, run.ExpiresAt, run.RetrySequence)
	if err != nil {
		return fmt.Errorf("create task run: %w", err)
	}
	return nil
}

func (p *PostgresStore) UpdateTaskRunCompletion(ctx context.Context, runID uuid.UUID, status model.TaskStatus, finished time.Time, summary []byte, errMsg string, metadata map[string]string, exitCode int32, errorCode string, expiresAt time.Time) error {
	meta := metadata
	if meta == nil {
		meta = map[string]string{}
	}
	metadataJSON, _ := json.Marshal(meta)
	_, err := p.pool.Exec(ctx, `UPDATE task_runs SET status=$2, finished_at=$3, summary=$4, error_message=$5, result_metadata=$6, exit_code=$7, error_code=$8, expires_at=$9 WHERE id=$1`, runID, string(status), finished, summary, errMsg, metadataJSON, exitCode, errorCode, expiresAt)
	if err != nil {
		return fmt.Errorf("update task run: %w", err)
	}
	return nil
}

func (p *PostgresStore) UpdateTaskRunStatusByLease(ctx context.Context, leaseID uuid.UUID, status model.TaskStatus) error {
	_, err := p.pool.Exec(ctx, `UPDATE task_runs SET status=$2 WHERE lease_id=$1`, leaseID, string(status))
	if err != nil {
		return fmt.Errorf("update task run by lease: %w", err)
	}
	return nil
}

func (p *PostgresStore) GetTaskRunByLease(ctx context.Context, leaseID uuid.UUID) (*model.TaskRun, error) {
	row := p.pool.QueryRow(ctx, `SELECT id, task_id, task_type, agent_id, lease_id, lease_expires, started_at, finished_at, status, error_message, summary, result_metadata, exit_code, error_code, expires_at, retry_sequence FROM task_runs WHERE lease_id=$1`, leaseID)
	var run model.TaskRun
	var metadata []byte
	if err := row.Scan(&run.ID, &run.TaskID, &run.TaskType, &run.AgentID, &run.LeaseID, &run.LeaseExpires, &run.StartedAt, &run.FinishedAt, &run.Status, &run.ErrorMessage, &run.Summary, &metadata, &run.ExitCode, &run.ErrorCode, &run.ExpiresAt, &run.RetrySequence); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, store.ErrNotFound
		}
		return nil, fmt.Errorf("scan task run: %w", err)
	}
	if len(metadata) > 0 {
		_ = json.Unmarshal(metadata, &run.Metadata)
	}
	return &run, nil
}

func (p *PostgresStore) SaveArtifacts(ctx context.Context, artifacts []model.Artifact) error {
	if len(artifacts) == 0 {
		return nil
	}
	batch := &pgx.Batch{}
	for _, art := range artifacts {
		id := art.ID
		if id == uuid.Nil {
			id = uuid.New()
		}
		batch.Queue(`INSERT INTO artifacts (id, task_run_id, name, mime_type, blob) VALUES ($1,$2,$3,$4,$5)`,
			id, art.TaskRunID, art.Name, art.MIMEType, art.Blob)
	}
	results := p.pool.SendBatch(ctx, batch)
	defer results.Close()
	for range artifacts {
		if _, err := results.Exec(); err != nil {
			return fmt.Errorf("insert artifact: %w", err)
		}
	}
	return nil
}

func (p *PostgresStore) GetArtifacts(ctx context.Context, ids []uuid.UUID) ([]model.Artifact, error) {
	if len(ids) == 0 {
		return nil, store.ErrNotFound
	}
	rows, err := p.pool.Query(ctx, `SELECT id, task_run_id, name, mime_type, blob FROM artifacts WHERE id = ANY($1)`, ids)
	if err != nil {
		return nil, fmt.Errorf("get artifacts: %w", err)
	}
	defer rows.Close()
	var artifacts []model.Artifact
	for rows.Next() {
		var art model.Artifact
		if err := rows.Scan(&art.ID, &art.TaskRunID, &art.Name, &art.MIMEType, &art.Blob); err != nil {
			return nil, fmt.Errorf("scan artifact: %w", err)
		}
		artifacts = append(artifacts, art)
	}
	if len(artifacts) == 0 {
		return nil, store.ErrNotFound
	}
	return artifacts, nil
}

func (p *PostgresStore) GetLatestTaskRun(ctx context.Context, taskID uuid.UUID) (*model.TaskRun, error) {
	query := `SELECT id, task_id, task_type, agent_id, lease_id, lease_expires, started_at, finished_at, status, error_message, summary, result_metadata, exit_code, error_code, expires_at, retry_sequence
FROM task_runs
WHERE task_id=$1
ORDER BY COALESCE(finished_at, started_at, lease_expires) DESC, id DESC
LIMIT 1`
	row := p.pool.QueryRow(ctx, query, taskID)
	var run model.TaskRun
	var metadata []byte
	if err := row.Scan(&run.ID, &run.TaskID, &run.TaskType, &run.AgentID, &run.LeaseID, &run.LeaseExpires, &run.StartedAt, &run.FinishedAt, &run.Status, &run.ErrorMessage, &run.Summary, &metadata, &run.ExitCode, &run.ErrorCode, &run.ExpiresAt, &run.RetrySequence); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, store.ErrNotFound
		}
		return nil, fmt.Errorf("scan latest run: %w", err)
	}
	if len(metadata) > 0 {
		_ = json.Unmarshal(metadata, &run.Metadata)
	}
	return &run, nil
}

func (p *PostgresStore) ListTaskRunsByAgent(ctx context.Context, agentID uuid.UUID, statuses []model.TaskStatus, limit int) ([]*model.TaskRun, error) {
	if limit <= 0 {
		limit = 100
	}
	query := `SELECT id, task_id, task_type, agent_id, lease_id, lease_expires, started_at, finished_at, status, error_message, summary, result_metadata, exit_code, error_code, expires_at, retry_sequence
FROM task_runs WHERE agent_id=$1`
	args := []interface{}{agentID}
	argPos := 2
	if len(statuses) > 0 {
		statusVals := make([]string, 0, len(statuses))
		for _, st := range statuses {
			statusVals = append(statusVals, string(st))
		}
		query += fmt.Sprintf(" AND status = ANY($%d)", argPos)
		args = append(args, statusVals)
		argPos++
	}
	query += fmt.Sprintf(" ORDER BY lease_expires ASC LIMIT $%d", argPos)
	args = append(args, limit)
	rows, err := p.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list task runs by agent: %w", err)
	}
	defer rows.Close()
	var runs []*model.TaskRun
	for rows.Next() {
		var run model.TaskRun
		var metadata []byte
		if err := rows.Scan(&run.ID, &run.TaskID, &run.TaskType, &run.AgentID, &run.LeaseID, &run.LeaseExpires, &run.StartedAt, &run.FinishedAt, &run.Status, &run.ErrorMessage, &run.Summary, &metadata, &run.ExitCode, &run.ErrorCode, &run.ExpiresAt, &run.RetrySequence); err != nil {
			return nil, fmt.Errorf("scan task run: %w", err)
		}
		if len(metadata) > 0 {
			_ = json.Unmarshal(metadata, &run.Metadata)
		}
		runs = append(runs, &run)
	}
	return runs, nil
}

func (p *PostgresStore) InsertSystemEvents(ctx context.Context, events []model.SystemEventRecord) error {
	if len(events) == 0 {
		return nil
	}
	batch := &pgx.Batch{}
	for _, evt := range events {
		id := evt.ID
		if id == uuid.Nil {
			id = uuid.New()
		}
		ts := evt.Timestamp
		if ts.IsZero() {
			ts = time.Now().UTC()
		}
		receivedAt := evt.ReceivedAt
		if receivedAt.IsZero() {
			receivedAt = time.Now().UTC()
		}
		metadataJSON, _ := json.Marshal(evt.Metadata)
		tagsJSON, _ := json.Marshal(evt.Tags)
		payloadJSON := []byte(nil)
		if len(evt.Payload) > 0 {
			payloadJSON = evt.Payload
		}
		rawJSON := []byte(nil)
		if len(evt.Raw) > 0 {
			rawJSON = evt.Raw
		}
		batch.Queue(`INSERT INTO system_events (
		    id, agent_id, agent_name, collector, collector_kind, event_type, source,
		    priority, storage_tier, event_timestamp, sequence, payload, metadata, tags, raw, received_at
		) VALUES (
		    $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16
		)`,
			id,
			evt.AgentID,
			evt.AgentName,
			evt.Collector,
			evt.CollectorKind,
			evt.EventType,
			evt.Source,
			evt.Priority,
			evt.StorageTier,
			ts,
			int64(evt.Sequence),
			payloadJSON,
			metadataJSON,
			tagsJSON,
			rawJSON,
			receivedAt,
		)
	}
	results := p.pool.SendBatch(ctx, batch)
	defer results.Close()
	for range events {
		if _, err := results.Exec(); err != nil {
			return fmt.Errorf("insert system event: %w", err)
		}
	}
	return nil
}

func (p *PostgresStore) CountSystemEvents(ctx context.Context, since time.Time) (int64, error) {
	var count int64
	var err error
	if since.IsZero() {
		err = p.pool.QueryRow(ctx, `SELECT COUNT(*) FROM system_events`).Scan(&count)
	} else {
		err = p.pool.QueryRow(ctx, `SELECT COUNT(*) FROM system_events WHERE received_at >= $1`, since).Scan(&count)
	}
	return count, err
}

func (p *PostgresStore) QuerySystemEvents(ctx context.Context, query store.SystemEventQuery) ([]model.SystemEventRecord, error) {
	limit := store.ClampEventQueryLimit(query.Limit)
	filter := buildEventFilters(query, true)
	filterSQL, args := filter.sql()
	order := "DESC"
	if query.SortAscending {
		order = "ASC"
	}
	var sb strings.Builder
	sb.WriteString(`SELECT id, agent_id, agent_name, collector, collector_kind, event_type, source, priority, storage_tier, event_timestamp, sequence, payload, metadata, tags, raw, received_at FROM system_events`)
	sb.WriteString(filterSQL)
	sb.WriteString(fmt.Sprintf(" ORDER BY received_at %s, id %s LIMIT $%d", order, order, filter.next))
	args = append(args, limit)
	rows, err := p.pool.Query(ctx, sb.String(), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	results := make([]model.SystemEventRecord, 0, limit)
	for rows.Next() {
		var evt model.SystemEventRecord
		var seq int64
		var payloadJSON, metadataJSON, tagsJSON, rawJSON []byte
		if err := rows.Scan(
			&evt.ID,
			&evt.AgentID,
			&evt.AgentName,
			&evt.Collector,
			&evt.CollectorKind,
			&evt.EventType,
			&evt.Source,
			&evt.Priority,
			&evt.StorageTier,
			&evt.Timestamp,
			&seq,
			&payloadJSON,
			&metadataJSON,
			&tagsJSON,
			&rawJSON,
			&evt.ReceivedAt,
		); err != nil {
			return nil, fmt.Errorf("scan system event: %w", err)
		}
		if len(payloadJSON) > 0 {
			evt.Payload = append([]byte(nil), payloadJSON...)
		}
		if len(rawJSON) > 0 {
			evt.Raw = append([]byte(nil), rawJSON...)
		}
		if len(metadataJSON) > 0 {
			_ = json.Unmarshal(metadataJSON, &evt.Metadata)
		}
		if len(tagsJSON) > 0 {
			_ = json.Unmarshal(tagsJSON, &evt.Tags)
		}
		if evt.Priority == "" {
			evt.Priority = store.DefaultPriorityLabel(evt.Priority)
		}
		if evt.StorageTier == "" {
			evt.StorageTier = store.DefaultTierLabel(evt.StorageTier)
		}
		evt.Sequence = uint64(seq)
		results = append(results, evt)
	}
	return results, rows.Err()
}

func (p *PostgresStore) AggregateSystemEvents(ctx context.Context, query store.SystemEventQuery) (store.SystemEventAggregates, error) {
	result := store.SystemEventAggregates{
		ByEventType: make(map[string]int64),
		BySource:    make(map[string]int64),
	}
	filter := buildEventFilters(query, false)
	filterSQL, args := filter.sql()
	countSQL := fmt.Sprintf("SELECT COUNT(*) FROM system_events%s", filterSQL)
	if err := p.pool.QueryRow(ctx, countSQL, args...).Scan(&result.Total); err != nil {
		return result, err
	}
	typeSQL := fmt.Sprintf("SELECT COALESCE(event_type,'') AS key, COUNT(*) FROM system_events%s GROUP BY 1", filterSQL)
	if err := p.collectAggregateCounts(ctx, typeSQL, args, result.ByEventType); err != nil {
		return result, err
	}
	sourceSQL := fmt.Sprintf("SELECT COALESCE(source,'') AS key, COUNT(*) FROM system_events%s GROUP BY 1", filterSQL)
	if err := p.collectAggregateCounts(ctx, sourceSQL, args, result.BySource); err != nil {
		return result, err
	}
	return result, nil
}

func (p *PostgresStore) collectAggregateCounts(ctx context.Context, sql string, args []any, dest map[string]int64) error {
	rows, err := p.pool.Query(ctx, sql, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var key string
		var count int64
		if err := rows.Scan(&key, &count); err != nil {
			return err
		}
		name := strings.TrimSpace(key)
		if name == "" {
			name = "(unknown)"
		}
		dest[name] = count
	}
	return rows.Err()
}

func (p *PostgresStore) UpsertCollectorConfig(ctx context.Context, snapshot *model.CollectorConfigSnapshot) error {
	if snapshot == nil || snapshot.AgentID == uuid.Nil {
		return errors.New("collector config: agent id required")
	}
	version := snapshot.Version
	if version == 0 {
		var current int64
		err := p.pool.QueryRow(ctx, `SELECT version FROM collector_configs WHERE agent_id=$1`, snapshot.AgentID).Scan(&current)
		if err != nil {
			if !errors.Is(err, pgx.ErrNoRows) {
				return err
			}
			version = 1
		} else {
			version = current + 1
		}
	}
	updatedAt := snapshot.UpdatedAt
	if updatedAt.IsZero() {
		updatedAt = time.Now().UTC()
	}
	_, err := p.pool.Exec(ctx, `INSERT INTO collector_configs (agent_id, version, config, updated_by, updated_at)
	    VALUES ($1,$2,$3,$4,$5)
	    ON CONFLICT (agent_id) DO UPDATE
	    SET version=EXCLUDED.version, config=EXCLUDED.config, updated_by=EXCLUDED.updated_by, updated_at=EXCLUDED.updated_at`,
		snapshot.AgentID, version, snapshot.Config, snapshot.UpdatedBy, updatedAt)
	return err
}

func (p *PostgresStore) GetCollectorConfig(ctx context.Context, agentID uuid.UUID) (*model.CollectorConfigSnapshot, error) {
	row := p.pool.QueryRow(ctx, `SELECT agent_id, version, config, updated_by, updated_at FROM collector_configs WHERE agent_id=$1`, agentID)
	var snap model.CollectorConfigSnapshot
	if err := row.Scan(&snap.AgentID, &snap.Version, &snap.Config, &snap.UpdatedBy, &snap.UpdatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, store.ErrNotFound
		}
		return nil, err
	}
	return &snap, nil
}

func (p *PostgresStore) ListCollectorConfigs(ctx context.Context) ([]*model.CollectorConfigSnapshot, error) {
	rows, err := p.pool.Query(ctx, `SELECT agent_id, version, config, updated_by, updated_at FROM collector_configs`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var snapshots []*model.CollectorConfigSnapshot
	for rows.Next() {
		var snap model.CollectorConfigSnapshot
		if err := rows.Scan(&snap.AgentID, &snap.Version, &snap.Config, &snap.UpdatedBy, &snap.UpdatedAt); err != nil {
			return nil, err
		}
		snapshots = append(snapshots, &snap)
	}
	return snapshots, rows.Err()
}

func (p *PostgresStore) UpsertCollectorStatus(ctx context.Context, status *model.CollectorStatusSnapshot) error {
	if status == nil || status.AgentID == uuid.Nil {
		return errors.New("collector status: agent id required")
	}
	statsJSON, _ := json.Marshal(status.Stats)
	metaJSON, _ := json.Marshal(status.Metadata)
	if status.UpdatedAt.IsZero() {
		status.UpdatedAt = time.Now().UTC()
	}
	_, err := p.pool.Exec(ctx, `INSERT INTO collector_statuses (agent_id, agent_name, version, state, last_error, stats, metadata, updated_at)
	    VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
	    ON CONFLICT (agent_id) DO UPDATE SET
	        agent_name=EXCLUDED.agent_name,
	        version=EXCLUDED.version,
	        state=EXCLUDED.state,
	        last_error=EXCLUDED.last_error,
	        stats=EXCLUDED.stats,
	        metadata=EXCLUDED.metadata,
	        updated_at=EXCLUDED.updated_at`,
		status.AgentID, status.AgentName, status.Version, status.State, status.LastError, statsJSON, metaJSON, status.UpdatedAt)
	return err
}

func (p *PostgresStore) ListCollectorStatuses(ctx context.Context) ([]*model.CollectorStatusSnapshot, error) {
	rows, err := p.pool.Query(ctx, `SELECT agent_id, agent_name, version, state, last_error, stats, metadata, updated_at FROM collector_statuses`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var statuses []*model.CollectorStatusSnapshot
	for rows.Next() {
		var snap model.CollectorStatusSnapshot
		var stats []byte
		var metadata []byte
		if err := rows.Scan(&snap.AgentID, &snap.AgentName, &snap.Version, &snap.State, &snap.LastError, &stats, &metadata, &snap.UpdatedAt); err != nil {
			return nil, err
		}
		if len(stats) > 0 {
			_ = json.Unmarshal(stats, &snap.Stats)
		}
		if len(metadata) > 0 {
			_ = json.Unmarshal(metadata, &snap.Metadata)
		}
		statuses = append(statuses, &snap)
	}
	return statuses, rows.Err()
}

func (p *PostgresStore) CreateCollectorRollout(ctx context.Context, rollout *model.CollectorRollout, targets []*model.CollectorRolloutTarget) error {
	if rollout == nil {
		return errors.New("collector rollout: rollout required")
	}
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if rollout.ID == uuid.Nil {
		rollout.ID = uuid.New()
	}
	now := time.Now().UTC()
	if rollout.CreatedAt.IsZero() {
		rollout.CreatedAt = now
	}
	if rollout.StartedAt.IsZero() {
		rollout.StartedAt = rollout.CreatedAt
	}
	if rollout.Status == "" {
		rollout.Status = model.CollectorRolloutStatusInProgress
	}
	rollout.TargetCount = len(targets)
	selectorJSON, _ := json.Marshal(rollout.Selector)
	_, err = tx.Exec(ctx, `INSERT INTO collector_rollouts (id, name, description, selector, status, config, version, strategy, created_by, created_at, started_at, completed_at, rolled_back_at, rollback_reason, grace_period_seconds, target_count, ack_count, failed_count, notes)
	    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)`,
		rollout.ID, rollout.Name, rollout.Description, selectorJSON, string(rollout.Status), rollout.Config, rollout.Version, rollout.Strategy, rollout.CreatedBy, rollout.CreatedAt, rollout.StartedAt, rollout.CompletedAt, rollout.RolledBackAt, rollout.RollbackReason, rollout.GracePeriodSeconds, rollout.TargetCount, rollout.AckCount, rollout.FailedCount, rollout.Notes)
	if err != nil {
		return err
	}
	for _, target := range targets {
		if target == nil || target.AgentID == uuid.Nil {
			continue
		}
		if target.RolloutID == uuid.Nil {
			target.RolloutID = rollout.ID
		}
		if target.CreatedAt.IsZero() {
			target.CreatedAt = now
		}
		if target.UpdatedAt.IsZero() {
			target.UpdatedAt = now
		}
		if target.State == "" {
			target.State = model.CollectorRolloutTargetStatePending
		}
		metadataJSON, _ := json.Marshal(target.Metadata)
		_, err = tx.Exec(ctx, `INSERT INTO collector_rollout_targets (rollout_id, agent_id, agent_name, desired_version, previous_version, previous_config, state, acked_at, last_heartbeat, last_error, metadata, created_at, updated_at)
		    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
			target.RolloutID, target.AgentID, target.AgentName, target.DesiredVersion, target.PreviousVersion, target.PreviousConfig, string(target.State), target.AckedAt, target.LastHeartbeat, target.LastError, metadataJSON, target.CreatedAt, target.UpdatedAt)
		if err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func (p *PostgresStore) UpdateCollectorRollout(ctx context.Context, rollout *model.CollectorRollout) error {
	if rollout == nil || rollout.ID == uuid.Nil {
		return errors.New("collector rollout: id required")
	}
	selectorJSON, _ := json.Marshal(rollout.Selector)
	_, err := p.pool.Exec(ctx, `UPDATE collector_rollouts SET name=$2, description=$3, selector=$4, status=$5, config=$6, version=$7, strategy=$8, created_by=$9, created_at=$10, started_at=$11, completed_at=$12, rolled_back_at=$13, rollback_reason=$14, grace_period_seconds=$15, target_count=$16, ack_count=$17, failed_count=$18, notes=$19 WHERE id=$1`,
		rollout.ID, rollout.Name, rollout.Description, selectorJSON, string(rollout.Status), rollout.Config, rollout.Version, rollout.Strategy, rollout.CreatedBy, rollout.CreatedAt, rollout.StartedAt, rollout.CompletedAt, rollout.RolledBackAt, rollout.RollbackReason, rollout.GracePeriodSeconds, rollout.TargetCount, rollout.AckCount, rollout.FailedCount, rollout.Notes)
	if err != nil {
		return err
	}
	return nil
}

func (p *PostgresStore) GetCollectorRollout(ctx context.Context, rolloutID uuid.UUID) (*model.CollectorRollout, error) {
	row := p.pool.QueryRow(ctx, `SELECT id, name, description, selector, status, config, version, strategy, created_by, created_at, started_at, completed_at, rolled_back_at, rollback_reason, grace_period_seconds, target_count, ack_count, failed_count, notes FROM collector_rollouts WHERE id=$1`, rolloutID)
	return scanCollectorRollout(row)
}

func (p *PostgresStore) ListCollectorRollouts(ctx context.Context, filter store.CollectorRolloutFilter) ([]*model.CollectorRollout, error) {
	limit := filter.Limit
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	var rows pgx.Rows
	var err error
	if len(filter.Statuses) > 0 {
		values := make([]string, len(filter.Statuses))
		for i, st := range filter.Statuses {
			values[i] = string(st)
		}
		rows, err = p.pool.Query(ctx, `SELECT id, name, description, selector, status, config, version, strategy, created_by, created_at, started_at, completed_at, rolled_back_at, rollback_reason, grace_period_seconds, target_count, ack_count, failed_count, notes FROM collector_rollouts WHERE status = ANY($1::text[]) ORDER BY created_at DESC LIMIT $2`, values, limit)
	} else {
		rows, err = p.pool.Query(ctx, `SELECT id, name, description, selector, status, config, version, strategy, created_by, created_at, started_at, completed_at, rolled_back_at, rollback_reason, grace_period_seconds, target_count, ack_count, failed_count, notes FROM collector_rollouts ORDER BY created_at DESC LIMIT $1`, limit)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var rollouts []*model.CollectorRollout
	for rows.Next() {
		rollout, err := scanCollectorRollout(rows)
		if err != nil {
			return nil, err
		}
		rollouts = append(rollouts, rollout)
	}
	return rollouts, rows.Err()
}

func (p *PostgresStore) ListCollectorRolloutTargets(ctx context.Context, rolloutID uuid.UUID) ([]*model.CollectorRolloutTarget, error) {
	rows, err := p.pool.Query(ctx, `SELECT rollout_id, agent_id, agent_name, desired_version, previous_version, previous_config, state, acked_at, last_heartbeat, last_error, metadata, created_at, updated_at FROM collector_rollout_targets WHERE rollout_id=$1`, rolloutID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var targets []*model.CollectorRolloutTarget
	for rows.Next() {
		target, err := scanCollectorRolloutTarget(rows)
		if err != nil {
			return nil, err
		}
		targets = append(targets, target)
	}
	if len(targets) == 0 {
		return nil, store.ErrNotFound
	}
	return targets, rows.Err()
}

func (p *PostgresStore) FindCollectorRolloutTargetsByAgent(ctx context.Context, agentID uuid.UUID) ([]*model.CollectorRolloutTarget, error) {
	rows, err := p.pool.Query(ctx, `SELECT rollout_id, agent_id, agent_name, desired_version, previous_version, previous_config, state, acked_at, last_heartbeat, last_error, metadata, created_at, updated_at FROM collector_rollout_targets WHERE agent_id=$1`, agentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var targets []*model.CollectorRolloutTarget
	for rows.Next() {
		target, err := scanCollectorRolloutTarget(rows)
		if err != nil {
			return nil, err
		}
		targets = append(targets, target)
	}
	return targets, rows.Err()
}

func (p *PostgresStore) UpdateCollectorRolloutTarget(ctx context.Context, target *model.CollectorRolloutTarget) error {
	if target == nil || target.RolloutID == uuid.Nil || target.AgentID == uuid.Nil {
		return errors.New("collector rollout target: invalid identifiers")
	}
	metadataJSON, _ := json.Marshal(target.Metadata)
	_, err := p.pool.Exec(ctx, `UPDATE collector_rollout_targets SET agent_name=$3, desired_version=$4, previous_version=$5, previous_config=$6, state=$7, acked_at=$8, last_heartbeat=$9, last_error=$10, metadata=$11, created_at=$12, updated_at=$13 WHERE rollout_id=$1 AND agent_id=$2`,
		target.RolloutID, target.AgentID, target.AgentName, target.DesiredVersion, target.PreviousVersion, target.PreviousConfig, string(target.State), target.AckedAt, target.LastHeartbeat, target.LastError, metadataJSON, target.CreatedAt, target.UpdatedAt)
	return err
}

func (p *PostgresStore) Ping(ctx context.Context) error {
	return p.pool.Ping(ctx)
}

func scanCollectorRollout(row pgx.Row) (*model.CollectorRollout, error) {
	var rollout model.CollectorRollout
	var selector []byte
	var status string
	if err := row.Scan(&rollout.ID, &rollout.Name, &rollout.Description, &selector, &status, &rollout.Config, &rollout.Version, &rollout.Strategy, &rollout.CreatedBy, &rollout.CreatedAt, &rollout.StartedAt, &rollout.CompletedAt, &rollout.RolledBackAt, &rollout.RollbackReason, &rollout.GracePeriodSeconds, &rollout.TargetCount, &rollout.AckCount, &rollout.FailedCount, &rollout.Notes); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, store.ErrNotFound
		}
		return nil, err
	}
	if len(selector) > 0 {
		_ = json.Unmarshal(selector, &rollout.Selector)
	}
	rollout.Status = model.CollectorRolloutStatus(status)
	return &rollout, nil
}

func scanCollectorRolloutTarget(row pgx.Row) (*model.CollectorRolloutTarget, error) {
	var target model.CollectorRolloutTarget
	var metadata []byte
	var state string
	if err := row.Scan(&target.RolloutID, &target.AgentID, &target.AgentName, &target.DesiredVersion, &target.PreviousVersion, &target.PreviousConfig, &state, &target.AckedAt, &target.LastHeartbeat, &target.LastError, &metadata, &target.CreatedAt, &target.UpdatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, store.ErrNotFound
		}
		return nil, err
	}
	if len(metadata) > 0 {
		_ = json.Unmarshal(metadata, &target.Metadata)
	}
	target.State = model.CollectorRolloutTargetState(state)
	return &target, nil
}

func scanAgent(row pgx.Row) (*model.Agent, error) {
	var agent model.Agent
	var labels []byte
	var caps []byte
	var metadata []byte
	if err := row.Scan(&agent.ID, &agent.Name, &labels, &agent.Platform, &agent.Version, &caps, &agent.Status, &agent.LastHeartbeat, &agent.Load, &agent.RunningTasks, &metadata, &agent.CreatedAt, &agent.UpdatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, store.ErrNotFound
		}
		return nil, fmt.Errorf("scan agent: %w", err)
	}
	if len(labels) > 0 {
		_ = json.Unmarshal(labels, &agent.Labels)
	}
	if len(caps) > 0 {
		_ = json.Unmarshal(caps, &agent.Capabilities)
	}
	if len(metadata) > 0 {
		_ = json.Unmarshal(metadata, &agent.Metadata)
	}
	return &agent, nil
}

var _ store.Store = (*PostgresStore)(nil)

// NewPostgresStore satisfies store.New factory expectations.
func NewPostgresStore(ctx context.Context, cfg config.DatabaseConfig) (store.Store, error) {
	return New(ctx, cfg)
}
