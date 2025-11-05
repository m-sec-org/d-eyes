-- Tasks table
drop table if exists artifacts cascade;
drop table if exists task_runs cascade;
drop table if exists tasks cascade;
drop table if exists agents cascade;

CREATE TABLE IF NOT EXISTS agents (
    id UUID PRIMARY KEY,
    name TEXT,
    labels JSONB DEFAULT '{}'::jsonb,
    platform TEXT,
    version TEXT,
    capabilities JSONB DEFAULT '[]'::jsonb,
    status TEXT NOT NULL DEFAULT 'offline',
    last_heartbeat TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE UNIQUE INDEX IF NOT EXISTS agents_name_idx ON agents (name);

CREATE TABLE IF NOT EXISTS tasks (
    id UUID PRIMARY KEY,
    type TEXT NOT NULL,
    priority INT NOT NULL,
    payload JSONB,
    status TEXT NOT NULL,
    retry_count INT NOT NULL DEFAULT 0,
    metadata JSONB DEFAULT '{}'::jsonb,
    created_by TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS tasks_status_idx ON tasks(status);
CREATE INDEX IF NOT EXISTS tasks_created_at_idx ON tasks(created_at DESC);
CREATE INDEX IF NOT EXISTS tasks_priority_idx ON tasks(priority ASC, created_at ASC);

CREATE TABLE IF NOT EXISTS task_runs (
    id UUID PRIMARY KEY,
    task_id UUID NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    agent_id UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    lease_id UUID UNIQUE NOT NULL,
    lease_expires TIMESTAMPTZ NOT NULL,
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    status TEXT NOT NULL,
    error_message TEXT,
    summary JSONB,
    retry_sequence INT NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS task_runs_task_idx ON task_runs(task_id, lease_expires DESC);

CREATE TABLE IF NOT EXISTS artifacts (
    id UUID PRIMARY KEY,
    task_run_id UUID NOT NULL REFERENCES task_runs(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    mime_type TEXT,
    blob BYTEA
);
