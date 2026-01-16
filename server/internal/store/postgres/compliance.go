package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/m-sec-org/d-eyes/server/internal/model"
)

func (p *PostgresStore) CreateComplianceFramework(ctx context.Context, framework *model.ComplianceFramework) error {
	if framework == nil {
		return fmt.Errorf("nil framework")
	}
	if framework.ID == uuid.Nil {
		framework.ID = uuid.New()
	}
	now := time.Now()
	framework.CreatedAt = now
	framework.UpdatedAt = now
	_, err := p.pool.Exec(ctx, `INSERT INTO compliance_frameworks (id, key, title, version, description, created_at, updated_at)
        VALUES ($1,$2,$3,$4,$5,$6,$7)`, framework.ID, framework.Key, framework.Title, framework.Version, framework.Description, framework.CreatedAt, framework.UpdatedAt)
	if err != nil {
		return fmt.Errorf("insert framework: %w", err)
	}
	return nil
}

func (p *PostgresStore) UpdateComplianceFramework(ctx context.Context, framework *model.ComplianceFramework) error {
	if framework == nil || framework.ID == uuid.Nil {
		return fmt.Errorf("invalid framework")
	}
	framework.UpdatedAt = time.Now()
	_, err := p.pool.Exec(ctx, `UPDATE compliance_frameworks SET key=$2, title=$3, version=$4, description=$5, updated_at=$6 WHERE id=$1`,
		framework.ID, framework.Key, framework.Title, framework.Version, framework.Description, framework.UpdatedAt)
	if err != nil {
		return fmt.Errorf("update framework: %w", err)
	}
	return nil
}

func (p *PostgresStore) ListComplianceFrameworks(ctx context.Context) ([]*model.ComplianceFramework, error) {
	rows, err := p.pool.Query(ctx, `SELECT id, key, title, version, description, created_at, updated_at FROM compliance_frameworks ORDER BY title`)
	if err != nil {
		return nil, fmt.Errorf("list frameworks: %w", err)
	}
	defer rows.Close()
	var result []*model.ComplianceFramework
	for rows.Next() {
		var fw model.ComplianceFramework
		if err := rows.Scan(&fw.ID, &fw.Key, &fw.Title, &fw.Version, &fw.Description, &fw.CreatedAt, &fw.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan framework: %w", err)
		}
		result = append(result, &fw)
	}
	return result, rows.Err()
}

func (p *PostgresStore) CreateComplianceControl(ctx context.Context, control *model.ComplianceControl) error {
	if control == nil {
		return fmt.Errorf("nil control")
	}
	if control.ID == uuid.Nil {
		control.ID = uuid.New()
	}
	now := time.Now()
	control.CreatedAt = now
	control.UpdatedAt = now
	refsJSON, _ := json.Marshal(control.References)
	_, err := p.pool.Exec(ctx, `INSERT INTO compliance_controls (id, framework_id, code, title, severity, description, refs, created_at, updated_at)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		control.ID, control.FrameworkID, control.Code, control.Title, control.Severity, control.Description, refsJSON, control.CreatedAt, control.UpdatedAt)
	if err != nil {
		return fmt.Errorf("insert control: %w", err)
	}
	return nil
}

func (p *PostgresStore) UpdateComplianceControl(ctx context.Context, control *model.ComplianceControl) error {
	if control == nil || control.ID == uuid.Nil {
		return fmt.Errorf("invalid control")
	}
	control.UpdatedAt = time.Now()
	refsJSON, _ := json.Marshal(control.References)
	_, err := p.pool.Exec(ctx, `UPDATE compliance_controls SET framework_id=$2, code=$3, title=$4, severity=$5, description=$6, refs=$7, updated_at=$8 WHERE id=$1`,
		control.ID, control.FrameworkID, control.Code, control.Title, control.Severity, control.Description, refsJSON, control.UpdatedAt)
	if err != nil {
		return fmt.Errorf("update control: %w", err)
	}
	return nil
}

func (p *PostgresStore) ListComplianceControls(ctx context.Context, frameworkID uuid.UUID) ([]*model.ComplianceControl, error) {
	rows, err := p.pool.Query(ctx, `SELECT id, framework_id, code, title, severity, description, refs, created_at, updated_at
        FROM compliance_controls WHERE framework_id = $1 ORDER BY code`, frameworkID)
	if err != nil {
		return nil, fmt.Errorf("list controls: %w", err)
	}
	defer rows.Close()
	var result []*model.ComplianceControl
	for rows.Next() {
		var ctrl model.ComplianceControl
		var refsJSON []byte
		if err := rows.Scan(&ctrl.ID, &ctrl.FrameworkID, &ctrl.Code, &ctrl.Title, &ctrl.Severity, &ctrl.Description, &refsJSON, &ctrl.CreatedAt, &ctrl.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan control: %w", err)
		}
		if len(refsJSON) > 0 {
			_ = json.Unmarshal(refsJSON, &ctrl.References)
		}
		result = append(result, &ctrl)
	}
	return result, rows.Err()
}

func (p *PostgresStore) CreateControlMapping(ctx context.Context, mapping *model.ControlMapping) error {
	if mapping == nil {
		return fmt.Errorf("nil mapping")
	}
	if mapping.ID == uuid.Nil {
		mapping.ID = uuid.New()
	}
	if mapping.TargetType == "" {
		mapping.TargetType = "task"
	}
	if mapping.CreatedAt.IsZero() {
		mapping.CreatedAt = time.Now()
	}
	_, err := p.pool.Exec(ctx, `INSERT INTO control_mappings (id, control_id, target_type, target_ref, metadata, created_at)
        VALUES ($1,$2,$3,$4,$5,$6)`,
		mapping.ID, mapping.ControlID, mapping.TargetType, mapping.TargetRef, mapping.Metadata, mapping.CreatedAt)
	if err != nil {
		return fmt.Errorf("insert mapping: %w", err)
	}
	return nil
}

func (p *PostgresStore) ListControlMappings(ctx context.Context, controlID uuid.UUID) ([]*model.ControlMapping, error) {
	rows, err := p.pool.Query(ctx, `SELECT id, control_id, target_type, target_ref, metadata, created_at FROM control_mappings WHERE control_id = $1`, controlID)
	if err != nil {
		return nil, fmt.Errorf("list mappings: %w", err)
	}
	defer rows.Close()
	var result []*model.ControlMapping
	for rows.Next() {
		var mapping model.ControlMapping
		if err := rows.Scan(&mapping.ID, &mapping.ControlID, &mapping.TargetType, &mapping.TargetRef, &mapping.Metadata, &mapping.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan mapping: %w", err)
		}
		result = append(result, &mapping)
	}
	return result, rows.Err()
}
