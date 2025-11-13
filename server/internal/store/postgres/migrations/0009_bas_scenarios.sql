CREATE TABLE IF NOT EXISTS bas_scenarios (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL,
    version INT NOT NULL DEFAULT 1,
    description TEXT,
    tags TEXT[],
    status TEXT NOT NULL,
    steps JSONB NOT NULL,
    resource_limits JSONB NOT NULL,
    network_boundaries TEXT[],
    requires_approval BOOLEAN NOT NULL DEFAULT FALSE,
    approval_state JSONB,
    approval_policy JSONB,
    dependencies UUID[],
    required_labels TEXT[],
    execution_plan JSONB NOT NULL,
    created_by TEXT,
    updated_by TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    published_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS bas_scenarios_status_idx ON bas_scenarios (status);
