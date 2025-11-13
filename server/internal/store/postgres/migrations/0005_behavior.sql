CREATE TABLE IF NOT EXISTS behavior_metrics (
    id UUID PRIMARY KEY,
    agent_id UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    load DOUBLE PRECISION,
    cpu_percent DOUBLE PRECISION,
    latency_ms DOUBLE PRECISION,
    running_tasks TEXT[],
    blocked_actions TEXT[],
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS behavior_metrics_agent_idx ON behavior_metrics(agent_id, created_at DESC);

CREATE TABLE IF NOT EXISTS behavior_events (
    id UUID PRIMARY KEY,
    agent_id UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    task_id UUID REFERENCES tasks(id) ON DELETE CASCADE,
    metadata JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS behavior_events_agent_idx ON behavior_events(agent_id, created_at DESC);

CREATE TABLE IF NOT EXISTS anomalies (
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
);

CREATE INDEX IF NOT EXISTS anomalies_agent_idx ON anomalies(agent_id, created_at DESC);
CREATE INDEX IF NOT EXISTS anomalies_task_idx ON anomalies(task_id, created_at DESC);
CREATE INDEX IF NOT EXISTS anomalies_status_idx ON anomalies(status);

CREATE TABLE IF NOT EXISTS behavior_graph_nodes (
    id UUID PRIMARY KEY,
    anomaly_id UUID NOT NULL REFERENCES anomalies(id) ON DELETE CASCADE,
    type TEXT NOT NULL,
    label TEXT,
    properties JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS behavior_graph_nodes_anomaly_idx ON behavior_graph_nodes(anomaly_id);

CREATE TABLE IF NOT EXISTS behavior_graph_edges (
    id UUID PRIMARY KEY,
    anomaly_id UUID NOT NULL REFERENCES anomalies(id) ON DELETE CASCADE,
    source_node UUID REFERENCES behavior_graph_nodes(id) ON DELETE CASCADE,
    target_node UUID REFERENCES behavior_graph_nodes(id) ON DELETE CASCADE,
    type TEXT,
    properties JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS behavior_graph_edges_anomaly_idx ON behavior_graph_edges(anomaly_id);
