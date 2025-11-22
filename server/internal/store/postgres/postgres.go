package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
            hash TEXT NOT NULL,
            filename TEXT,
            size BIGINT,
            status TEXT NOT NULL,
            artifact_ids UUID[] DEFAULT '{}'::uuid[],
            task_run_id UUID NOT NULL REFERENCES task_runs(id) ON DELETE CASCADE,
            agent_id UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
            metadata JSONB DEFAULT '{}'::jsonb,
            last_error TEXT,
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
            next_run_at TIMESTAMPTZ,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            task_run_id UUID REFERENCES task_runs(id) ON DELETE CASCADE,
            agent_id UUID REFERENCES agents(id) ON DELETE CASCADE,
            artifact_ids UUID[] DEFAULT '{}'::uuid[],
            metadata JSONB DEFAULT '{}'::jsonb
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
		`CREATE TABLE IF NOT EXISTS anomalies (
		    id UUID PRIMARY KEY,
		    agent_id UUID REFERENCES agents(id) ON DELETE CASCADE,
		    severity TEXT,
		    score DOUBLE PRECISION,
		    summary JSONB,
		    status TEXT,
		    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`,
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

func (p *PostgresStore) ListTasks(ctx context.Context, statuses []model.TaskStatus, limit int) ([]*model.Task, error) {
	if limit <= 0 {
		limit = 100
	}
	var (
		rows pgx.Rows
		err  error
	)
	if len(statuses) == 0 {
		query := `SELECT id, type, profile, priority, payload, status, retry_count, metadata, created_by, created_at, updated_at FROM tasks ORDER BY created_at DESC LIMIT $1`
		rows, err = p.pool.Query(ctx, query, limit)
	} else {
		statusVals := make([]string, len(statuses))
		for i, st := range statuses {
			statusVals[i] = string(st)
		}
		query := `SELECT id, type, profile, priority, payload, status, retry_count, metadata, created_by, created_at, updated_at FROM tasks WHERE status = ANY($1) ORDER BY created_at DESC LIMIT $2`
		rows, err = p.pool.Query(ctx, query, statusVals, limit)
	}
	if err != nil {
		return nil, fmt.Errorf("list tasks: %w", err)
	}
	defer rows.Close()
	var res []*model.Task
	for rows.Next() {
		var task model.Task
		var payload []byte
		var metadata []byte
		if err := rows.Scan(&task.ID, &task.Type, &task.Profile, &task.Priority, &payload, &task.Status, &task.RetryCount, &metadata, &task.CreatedBy, &task.CreatedAt, &task.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan task: %w", err)
		}
		task.Payload = append([]byte(nil), payload...)
		if len(metadata) > 0 {
			_ = json.Unmarshal(metadata, &task.Metadata)
		}
		res = append(res, &task)
	}
	return res, nil
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

func (p *PostgresStore) Ping(ctx context.Context) error {
	return p.pool.Ping(ctx)
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
