CREATE TABLE IF NOT EXISTS compliance_findings (
    id UUID PRIMARY KEY,
    framework_id UUID REFERENCES compliance_frameworks(id) ON DELETE SET NULL,
    control_id UUID REFERENCES compliance_controls(id) ON DELETE CASCADE,
    asset_ref TEXT,
    status TEXT NOT NULL,
    evidence JSONB,
    remediation_logs JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS compliance_findings_framework_idx ON compliance_findings(framework_id, status);

