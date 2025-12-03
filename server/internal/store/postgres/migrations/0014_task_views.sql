CREATE TABLE IF NOT EXISTS task_views (
    id UUID PRIMARY KEY,
    owner TEXT NOT NULL,
    name TEXT NOT NULL,
    filters JSONB NOT NULL DEFAULT '{}'::jsonb,
    page_size INTEGER NOT NULL DEFAULT 50,
    is_default BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_task_views_owner ON task_views (owner) WHERE deleted_at IS NULL;
