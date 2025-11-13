CREATE TABLE IF NOT EXISTS threat_intel_samples (
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
);

CREATE INDEX IF NOT EXISTS threat_intel_samples_hash_idx ON threat_intel_samples(hash);

CREATE TABLE IF NOT EXISTS threat_intel_jobs (
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
);

CREATE INDEX IF NOT EXISTS threat_intel_jobs_status_idx ON threat_intel_jobs(status, next_run_at);
CREATE INDEX IF NOT EXISTS threat_intel_jobs_indicator_idx ON threat_intel_jobs(indicator);

CREATE TABLE IF NOT EXISTS threat_intel_verdicts (
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
);

CREATE INDEX IF NOT EXISTS threat_intel_verdicts_indicator_idx ON threat_intel_verdicts(indicator);
