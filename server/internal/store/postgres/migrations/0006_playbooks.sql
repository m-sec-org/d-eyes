CREATE TABLE IF NOT EXISTS playbooks (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    status TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 1,
    trigger JSONB NOT NULL,
    conditions TEXT[],
    approvals JSONB,
    actions JSONB NOT NULL,
    rollback JSONB,
    created_by TEXT,
    updated_by TEXT,
    approved_by TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_run_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS playbooks_status_idx ON playbooks(status);

CREATE TABLE IF NOT EXISTS playbook_runs (
    id UUID PRIMARY KEY,
    playbook_id UUID NOT NULL REFERENCES playbooks(id) ON DELETE CASCADE,
    status TEXT NOT NULL,
    trigger_type TEXT,
    event JSONB,
    steps JSONB,
    result JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS playbook_runs_pb_idx ON playbook_runs(playbook_id, created_at DESC);
