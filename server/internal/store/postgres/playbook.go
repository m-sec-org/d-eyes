package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/m-sec-org/d-eyes/server/internal/model"
)

func (p *PostgresStore) CreatePlaybook(ctx context.Context, playbook *model.Playbook) error {
	if playbook == nil {
		return fmt.Errorf("nil playbook")
	}
	if playbook.ID == uuid.Nil {
		playbook.ID = uuid.New()
	}
	now := time.Now()
	if playbook.CreatedAt.IsZero() {
		playbook.CreatedAt = now
	}
	playbook.UpdatedAt = now
	triggerJSON, _ := json.Marshal(playbook.Trigger)
	approvalsJSON, _ := json.Marshal(playbook.Approvals)
	actionsJSON, _ := json.Marshal(playbook.Actions)
	rollbackJSON, _ := json.Marshal(playbook.Rollback)
	_, err := p.pool.Exec(ctx, `INSERT INTO playbooks (
        id, name, description, status, version, trigger, conditions, approvals, actions, rollback,
        created_by, updated_by, approved_by, created_at, updated_at, last_run_at)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)`,
		playbook.ID, playbook.Name, playbook.Description, playbook.Status, playbook.Version,
		triggerJSON, playbook.Conditions, approvalsJSON, actionsJSON, rollbackJSON, playbook.CreatedBy,
		playbook.UpdatedBy, playbook.ApprovedBy, playbook.CreatedAt, playbook.UpdatedAt, playbook.LastRunAt)
	if err != nil {
		return fmt.Errorf("insert playbook: %w", err)
	}
	return nil
}

func (p *PostgresStore) UpdatePlaybook(ctx context.Context, playbook *model.Playbook) error {
	if playbook == nil || playbook.ID == uuid.Nil {
		return fmt.Errorf("invalid playbook")
	}
	playbook.UpdatedAt = time.Now()
	triggerJSON, _ := json.Marshal(playbook.Trigger)
	approvalsJSON, _ := json.Marshal(playbook.Approvals)
	actionsJSON, _ := json.Marshal(playbook.Actions)
	rollbackJSON, _ := json.Marshal(playbook.Rollback)
	_, err := p.pool.Exec(ctx, `UPDATE playbooks SET
        name=$2, description=$3, status=$4, version=$5, trigger=$6, conditions=$7,
        approvals=$8, actions=$9, rollback=$10, updated_by=$11, approved_by=$12,
        updated_at=$13, last_run_at=$14
        WHERE id=$1`,
		playbook.ID, playbook.Name, playbook.Description, playbook.Status, playbook.Version,
		triggerJSON, playbook.Conditions, approvalsJSON, actionsJSON, rollbackJSON,
		playbook.UpdatedBy, playbook.ApprovedBy, playbook.UpdatedAt, playbook.LastRunAt)
	if err != nil {
		return fmt.Errorf("update playbook: %w", err)
	}
	return nil
}

func (p *PostgresStore) GetPlaybook(ctx context.Context, id uuid.UUID) (*model.Playbook, error) {
	row := p.pool.QueryRow(ctx, `SELECT id, name, description, status, version, trigger, conditions,
        approvals, actions, rollback, created_by, updated_by, approved_by, created_at, updated_at, last_run_at
        FROM playbooks WHERE id = $1`, id)
	var pb model.Playbook
	var triggerJSON, approvalsJSON, actionsJSON, rollbackJSON []byte
	if err := row.Scan(&pb.ID, &pb.Name, &pb.Description, &pb.Status, &pb.Version,
		&triggerJSON, &pb.Conditions, &approvalsJSON, &actionsJSON, &rollbackJSON,
		&pb.CreatedBy, &pb.UpdatedBy, &pb.ApprovedBy, &pb.CreatedAt, &pb.UpdatedAt, &pb.LastRunAt); err != nil {
		return nil, fmt.Errorf("get playbook: %w", err)
	}
	_ = json.Unmarshal(triggerJSON, &pb.Trigger)
	_ = json.Unmarshal(approvalsJSON, &pb.Approvals)
	_ = json.Unmarshal(actionsJSON, &pb.Actions)
	_ = json.Unmarshal(rollbackJSON, &pb.Rollback)
	return &pb, nil
}

func (p *PostgresStore) ListPlaybooks(ctx context.Context, limit int) ([]*model.Playbook, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := p.pool.Query(ctx, `SELECT id, name, description, status, version, trigger, conditions,
        approvals, actions, rollback, created_by, updated_by, approved_by, created_at, updated_at, last_run_at
        FROM playbooks ORDER BY updated_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("list playbooks: %w", err)
	}
	defer rows.Close()
	var results []*model.Playbook
	for rows.Next() {
		var pb model.Playbook
		var triggerJSON, approvalsJSON, actionsJSON, rollbackJSON []byte
		if err := rows.Scan(&pb.ID, &pb.Name, &pb.Description, &pb.Status, &pb.Version,
			&triggerJSON, &pb.Conditions, &approvalsJSON, &actionsJSON, &rollbackJSON,
			&pb.CreatedBy, &pb.UpdatedBy, &pb.ApprovedBy, &pb.CreatedAt, &pb.UpdatedAt, &pb.LastRunAt); err != nil {
			return nil, fmt.Errorf("scan playbook: %w", err)
		}
		_ = json.Unmarshal(triggerJSON, &pb.Trigger)
		_ = json.Unmarshal(approvalsJSON, &pb.Approvals)
		_ = json.Unmarshal(actionsJSON, &pb.Actions)
		_ = json.Unmarshal(rollbackJSON, &pb.Rollback)
		results = append(results, &pb)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate playbooks: %w", err)
	}
	return results, nil
}

func (p *PostgresStore) CreatePlaybookRun(ctx context.Context, run *model.PlaybookRun) error {
	if run == nil {
		return fmt.Errorf("nil playbook run")
	}
	if run.ID == uuid.Nil {
		run.ID = uuid.New()
	}
	now := time.Now()
	if run.CreatedAt.IsZero() {
		run.CreatedAt = now
	}
	if run.UpdatedAt.IsZero() {
		run.UpdatedAt = now
	}
	eventJSON, _ := json.Marshal(run.Event)
	stepsJSON, _ := json.Marshal(run.Steps)
	resultJSON, _ := json.Marshal(run.Result)
	_, err := p.pool.Exec(ctx, `INSERT INTO playbook_runs (
        id, playbook_id, status, trigger_type, event, steps, result, created_at, updated_at, completed_at)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		run.ID, run.PlaybookID, run.Status, run.TriggerType, eventJSON, stepsJSON, resultJSON, run.CreatedAt, run.UpdatedAt, run.CompletedAt)
	if err != nil {
		return fmt.Errorf("insert playbook run: %w", err)
	}
	return nil
}

func (p *PostgresStore) UpdatePlaybookRun(ctx context.Context, run *model.PlaybookRun) error {
	if run == nil || run.ID == uuid.Nil {
		return fmt.Errorf("invalid playbook run")
	}
	run.UpdatedAt = time.Now()
	eventJSON, _ := json.Marshal(run.Event)
	stepsJSON, _ := json.Marshal(run.Steps)
	resultJSON, _ := json.Marshal(run.Result)
	_, err := p.pool.Exec(ctx, `UPDATE playbook_runs SET
        status=$2, trigger_type=$3, event=$4, steps=$5, result=$6, updated_at=$7, completed_at=$8
        WHERE id=$1`,
		run.ID, run.Status, run.TriggerType, eventJSON, stepsJSON, resultJSON, run.UpdatedAt, run.CompletedAt)
	if err != nil {
		return fmt.Errorf("update playbook run: %w", err)
	}
	return nil
}

func (p *PostgresStore) ListPlaybookRuns(ctx context.Context, playbookID uuid.UUID, limit int) ([]*model.PlaybookRun, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := p.pool.Query(ctx, `SELECT id, playbook_id, status, trigger_type, event, steps, result, created_at, updated_at, completed_at
        FROM playbook_runs WHERE playbook_id = $1 ORDER BY created_at DESC LIMIT $2`, playbookID, limit)
	if err != nil {
		return nil, fmt.Errorf("list playbook runs: %w", err)
	}
	defer rows.Close()
	var results []*model.PlaybookRun
	for rows.Next() {
		var run model.PlaybookRun
		var eventJSON, stepsJSON, resultJSON []byte
		if err := rows.Scan(&run.ID, &run.PlaybookID, &run.Status, &run.TriggerType, &eventJSON, &stepsJSON, &resultJSON,
			&run.CreatedAt, &run.UpdatedAt, &run.CompletedAt); err != nil {
			return nil, fmt.Errorf("scan playbook run: %w", err)
		}
		_ = json.Unmarshal(eventJSON, &run.Event)
		_ = json.Unmarshal(stepsJSON, &run.Steps)
		_ = json.Unmarshal(resultJSON, &run.Result)
		results = append(results, &run)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate playbook runs: %w", err)
	}
	return results, nil
}
