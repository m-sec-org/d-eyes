ALTER TABLE task_runs
    ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS task_runs_expires_at_idx ON task_runs (expires_at);
