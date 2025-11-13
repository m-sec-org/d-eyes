package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/m-sec-org/d-eyes/server/internal/model"
	"github.com/m-sec-org/d-eyes/server/internal/store"
)

func (p *PostgresStore) CreateBASScenario(ctx context.Context, scenario *model.BASScenario) error {
	if scenario == nil {
		return fmt.Errorf("nil bas scenario")
	}
	if scenario.ID == uuid.Nil {
		scenario.ID = uuid.New()
	}
	now := time.Now().UTC()
	if scenario.CreatedAt.IsZero() {
		scenario.CreatedAt = now
	}
	scenario.UpdatedAt = now
	stepsJSON, _ := json.Marshal(scenario.Steps)
	limitsJSON, _ := json.Marshal(scenario.ResourceLimits)
	approvalJSON, _ := json.Marshal(scenario.Approval)
	policyJSON, _ := json.Marshal(scenario.ApprovalPolicy)
	planJSON, _ := json.Marshal(scenario.ExecutionPlan)
	_, err := p.pool.Exec(ctx, `
        INSERT INTO bas_scenarios (
            id, name, version, description, tags, status, steps, resource_limits,
            network_boundaries, requires_approval, approval_state, approval_policy,
            dependencies, required_labels, execution_plan, created_by, updated_by,
            created_at, updated_at, published_at
        )
        VALUES (
            $1,$2,$3,$4,$5,$6,$7,$8,
            $9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20
        )`,
		scenario.ID, scenario.Name, scenario.Version, scenario.Description, scenario.Tags, scenario.Status,
		stepsJSON, limitsJSON, scenario.NetworkBoundaries, scenario.RequiresApproval, approvalJSON, policyJSON,
		scenario.Dependencies, scenario.RequiredLabels, planJSON, scenario.CreatedBy, scenario.UpdatedBy,
		scenario.CreatedAt, scenario.UpdatedAt, scenario.PublishedAt,
	)
	if err != nil {
		return fmt.Errorf("insert bas scenario: %w", err)
	}
	return nil
}

func (p *PostgresStore) UpdateBASScenario(ctx context.Context, scenario *model.BASScenario) error {
	if scenario == nil || scenario.ID == uuid.Nil {
		return fmt.Errorf("invalid bas scenario")
	}
	scenario.UpdatedAt = time.Now().UTC()
	stepsJSON, _ := json.Marshal(scenario.Steps)
	limitsJSON, _ := json.Marshal(scenario.ResourceLimits)
	approvalJSON, _ := json.Marshal(scenario.Approval)
	policyJSON, _ := json.Marshal(scenario.ApprovalPolicy)
	planJSON, _ := json.Marshal(scenario.ExecutionPlan)
	_, err := p.pool.Exec(ctx, `
        UPDATE bas_scenarios SET
            name=$2, version=$3, description=$4, tags=$5, status=$6,
            steps=$7, resource_limits=$8, network_boundaries=$9, requires_approval=$10,
            approval_state=$11, approval_policy=$12, dependencies=$13, required_labels=$14,
            execution_plan=$15, created_by=$16, updated_by=$17, created_at=$18, updated_at=$19, published_at=$20
        WHERE id=$1`,
		scenario.ID, scenario.Name, scenario.Version, scenario.Description, scenario.Tags, scenario.Status,
		stepsJSON, limitsJSON, scenario.NetworkBoundaries, scenario.RequiresApproval, approvalJSON, policyJSON,
		scenario.Dependencies, scenario.RequiredLabels, planJSON, scenario.CreatedBy, scenario.UpdatedBy,
		scenario.CreatedAt, scenario.UpdatedAt, scenario.PublishedAt,
	)
	if err != nil {
		return fmt.Errorf("update bas scenario: %w", err)
	}
	return nil
}

func (p *PostgresStore) GetBASScenario(ctx context.Context, id uuid.UUID) (*model.BASScenario, error) {
	row := p.pool.QueryRow(ctx, `
        SELECT id, name, version, description, tags, status, steps, resource_limits,
               network_boundaries, requires_approval, approval_state, approval_policy,
               dependencies, required_labels, execution_plan, created_by, updated_by,
               created_at, updated_at, published_at
        FROM bas_scenarios WHERE id = $1`, id)
	return scanBASScenario(row)
}

func (p *PostgresStore) ListBASScenarios(ctx context.Context) ([]*model.BASScenario, error) {
	rows, err := p.pool.Query(ctx, `
        SELECT id, name, version, description, tags, status, steps, resource_limits,
               network_boundaries, requires_approval, approval_state, approval_policy,
               dependencies, required_labels, execution_plan, created_by, updated_by,
               created_at, updated_at, published_at
        FROM bas_scenarios`)
	if err != nil {
		return nil, fmt.Errorf("list bas scenarios: %w", err)
	}
	defer rows.Close()
	var results []*model.BASScenario
	for rows.Next() {
		scenario, err := scanBASScenario(rows)
		if err != nil {
			return nil, err
		}
		results = append(results, scenario)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate bas scenarios: %w", err)
	}
	return results, nil
}

func (p *PostgresStore) DeleteBASScenario(ctx context.Context, id uuid.UUID) error {
	cmdTag, err := p.pool.Exec(ctx, `DELETE FROM bas_scenarios WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("delete bas scenario: %w", err)
	}
	if cmdTag.RowsAffected() == 0 {
		return store.ErrNotFound
	}
	return nil
}

func scanBASScenario(row pgx.Row) (*model.BASScenario, error) {
	var scenario model.BASScenario
	var stepsJSON, limitsJSON, approvalJSON, policyJSON, planJSON []byte
	if err := row.Scan(
		&scenario.ID, &scenario.Name, &scenario.Version, &scenario.Description, &scenario.Tags, &scenario.Status,
		&stepsJSON, &limitsJSON, &scenario.NetworkBoundaries, &scenario.RequiresApproval, &approvalJSON, &policyJSON,
		&scenario.Dependencies, &scenario.RequiredLabels, &planJSON, &scenario.CreatedBy, &scenario.UpdatedBy,
		&scenario.CreatedAt, &scenario.UpdatedAt, &scenario.PublishedAt,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, store.ErrNotFound
		}
		return nil, fmt.Errorf("scan bas scenario: %w", err)
	}
	_ = json.Unmarshal(stepsJSON, &scenario.Steps)
	_ = json.Unmarshal(limitsJSON, &scenario.ResourceLimits)
	_ = json.Unmarshal(approvalJSON, &scenario.Approval)
	_ = json.Unmarshal(policyJSON, &scenario.ApprovalPolicy)
	_ = json.Unmarshal(planJSON, &scenario.ExecutionPlan)
	return &scenario, nil
}
