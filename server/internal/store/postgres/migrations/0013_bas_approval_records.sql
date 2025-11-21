ALTER TABLE bas_scenarios
    ADD COLUMN IF NOT EXISTS approval_records JSONB DEFAULT '[]'::jsonb;

UPDATE bas_scenarios
SET approval_records = COALESCE(approval_records, '[]'::jsonb);
