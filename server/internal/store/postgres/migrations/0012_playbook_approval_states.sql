ALTER TABLE playbooks
    ADD COLUMN IF NOT EXISTS approval_states JSONB;

UPDATE playbooks
SET approval_states = COALESCE(approval_states, '[]'::jsonb);
