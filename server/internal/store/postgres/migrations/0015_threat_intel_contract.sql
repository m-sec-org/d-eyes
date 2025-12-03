ALTER TABLE threat_intel_samples ADD COLUMN IF NOT EXISTS indicator TEXT;
ALTER TABLE threat_intel_samples ADD COLUMN IF NOT EXISTS classification TEXT;
ALTER TABLE threat_intel_samples ADD COLUMN IF NOT EXISTS source TEXT;
ALTER TABLE threat_intel_samples ADD COLUMN IF NOT EXISTS artifact_details JSONB DEFAULT '{}'::jsonb;
ALTER TABLE threat_intel_samples ADD COLUMN IF NOT EXISTS last_error_code TEXT;

ALTER TABLE threat_intel_jobs ADD COLUMN IF NOT EXISTS error_code TEXT;
ALTER TABLE threat_intel_jobs ADD COLUMN IF NOT EXISTS last_transition_at TIMESTAMPTZ DEFAULT now();
ALTER TABLE threat_intel_jobs ADD COLUMN IF NOT EXISTS summary JSONB DEFAULT '{}'::jsonb;
