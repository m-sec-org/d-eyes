package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/m-sec-org/d-eyes/server/internal/model"
)

func (p *PostgresStore) CreateComplianceFinding(ctx context.Context, finding *model.ComplianceFinding) error {
	if finding == nil {
		return fmt.Errorf("nil finding")
	}
	if finding.ID == uuid.Nil {
		finding.ID = uuid.New()
	}
	now := time.Now()
	if finding.CreatedAt.IsZero() {
		finding.CreatedAt = now
	}
	finding.UpdatedAt = finding.CreatedAt
	notesJSON, _ := json.Marshal(finding.RemediationLogs)
	evidenceJSON, _ := json.Marshal(finding.Evidence)
	_, err := p.pool.Exec(ctx, `INSERT INTO compliance_findings (
        id, framework_id, control_id, asset_ref, status, evidence, remediation_logs, created_at, updated_at)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		finding.ID, finding.FrameworkID, finding.ControlID, finding.AssetRef, finding.Status, evidenceJSON, notesJSON, finding.CreatedAt, finding.UpdatedAt)
	if err != nil {
		return fmt.Errorf("insert finding: %w", err)
	}
	return nil
}

func (p *PostgresStore) UpdateComplianceFinding(ctx context.Context, finding *model.ComplianceFinding) error {
	if finding == nil || finding.ID == uuid.Nil {
		return fmt.Errorf("invalid finding")
	}
	finding.UpdatedAt = time.Now()
	notesJSON, _ := json.Marshal(finding.RemediationLogs)
	evidenceJSON, _ := json.Marshal(finding.Evidence)
	_, err := p.pool.Exec(ctx, `UPDATE compliance_findings SET
        framework_id=$2, control_id=$3, asset_ref=$4, status=$5, evidence=$6, remediation_logs=$7, updated_at=$8 WHERE id=$1`,
		finding.ID, finding.FrameworkID, finding.ControlID, finding.AssetRef, finding.Status, evidenceJSON, notesJSON, finding.UpdatedAt)
	if err != nil {
		return fmt.Errorf("update finding: %w", err)
	}
	return nil
}

func (p *PostgresStore) GetComplianceFinding(ctx context.Context, id uuid.UUID) (*model.ComplianceFinding, error) {
	row := p.pool.QueryRow(ctx, `SELECT id, framework_id, control_id, asset_ref, status, evidence, remediation_logs, created_at, updated_at
        FROM compliance_findings WHERE id = $1`, id)
	var finding model.ComplianceFinding
	var evidenceJSON, notesJSON []byte
	if err := row.Scan(&finding.ID, &finding.FrameworkID, &finding.ControlID, &finding.AssetRef, &finding.Status,
		&evidenceJSON, &notesJSON, &finding.CreatedAt, &finding.UpdatedAt); err != nil {
		return nil, fmt.Errorf("get finding: %w", err)
	}
	if len(evidenceJSON) > 0 {
		_ = json.Unmarshal(evidenceJSON, &finding.Evidence)
	}
	if len(notesJSON) > 0 {
		_ = json.Unmarshal(notesJSON, &finding.RemediationLogs)
	}
	return &finding, nil
}

func (p *PostgresStore) ListComplianceFindings(ctx context.Context, frameworkID uuid.UUID, status string) ([]*model.ComplianceFinding, error) {
	query := `SELECT id, framework_id, control_id, asset_ref, status, evidence, remediation_logs, created_at, updated_at
        FROM compliance_findings`
	args := []interface{}{}
	where := ""
	argIdx := 1
	if frameworkID != uuid.Nil {
		where += fmt.Sprintf(" framework_id = $%d", argIdx)
		args = append(args, frameworkID)
		argIdx++
	}
	if status != "" {
		if where != "" {
			where += " AND"
		}
		where += fmt.Sprintf(" status = $%d", argIdx)
		args = append(args, status)
		argIdx++
	}
	if where != "" {
		query += " WHERE" + where
	}
	query += " ORDER BY updated_at DESC"
	rows, err := p.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list findings: %w", err)
	}
	defer rows.Close()
	var findings []*model.ComplianceFinding
	for rows.Next() {
		var finding model.ComplianceFinding
		var evidenceJSON, notesJSON []byte
		if err := rows.Scan(&finding.ID, &finding.FrameworkID, &finding.ControlID, &finding.AssetRef, &finding.Status,
			&evidenceJSON, &notesJSON, &finding.CreatedAt, &finding.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan finding: %w", err)
		}
		if len(evidenceJSON) > 0 {
			_ = json.Unmarshal(evidenceJSON, &finding.Evidence)
		}
		if len(notesJSON) > 0 {
			_ = json.Unmarshal(notesJSON, &finding.RemediationLogs)
		}
		findings = append(findings, &finding)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate findings: %w", err)
	}
	return findings, nil
}
