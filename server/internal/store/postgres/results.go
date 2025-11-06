package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/m-sec-org/d-eyes/server/internal/model"
)

func (p *PostgresStore) InsertTaskResult(ctx context.Context, result *model.TaskResult) error {
	if result == nil {
		return fmt.Errorf("nil task result")
	}
	if result.ID == uuid.Nil {
		result.ID = uuid.New()
	}
	metadataJSON, _ := json.Marshal(result.Metadata)
	summaryJSON := json.RawMessage(result.Summary)
	if _, err := p.pool.Exec(ctx, `INSERT INTO task_results (
            id, task_id, task_type, profile, run_id, agent_id, status, metadata, summary, error_message, exit_code, error_code, scenario_id, scenario_name, completed_at, created_at
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)`,
		result.ID, result.TaskID, string(result.TaskType), result.Profile, result.RunID, result.AgentID,
		string(result.Status), metadataJSON, summaryJSON, result.ErrorMessage, result.ExitCode,
		result.ErrorCode, result.ScenarioID, result.ScenarioName, result.CompletedAt, result.CreatedAt); err != nil {
		return fmt.Errorf("insert task result: %w", err)
	}
	return nil
}

func (p *PostgresStore) ArchiveTaskResults(ctx context.Context, before time.Time) (int, error) {
	if before.IsZero() {
		return 0, nil
	}
	res, err := p.pool.Exec(ctx, `DELETE FROM task_results WHERE completed_at < $1`, before)
	if err != nil {
		return 0, fmt.Errorf("archive task results: %w", err)
	}
	return int(res.RowsAffected()), nil
}

func (p *PostgresStore) ListTaskResults(ctx context.Context, taskType model.TaskType, limit int) ([]*model.TaskResult, error) {
	if limit <= 0 {
		limit = 50
	}
	query := `SELECT id, task_id, task_type, profile, run_id, agent_id, status, metadata, summary, error_message, exit_code, error_code, scenario_id, scenario_name, completed_at, created_at
FROM task_results`
	var rows pgx.Rows
	var err error
	if taskType != "" {
		query += ` WHERE task_type = $1 ORDER BY completed_at DESC, id DESC LIMIT $2`
		rows, err = p.pool.Query(ctx, query, string(taskType), limit)
	} else {
		query += ` ORDER BY completed_at DESC, id DESC LIMIT $1`
		rows, err = p.pool.Query(ctx, query, limit)
	}
	if err != nil {
		return nil, fmt.Errorf("list task results: %w", err)
	}
	defer rows.Close()

	results := make([]*model.TaskResult, 0, limit)
	for rows.Next() {
		var res model.TaskResult
		var metadataJSON []byte
		var summaryJSON []byte
		if err := rows.Scan(&res.ID, &res.TaskID, &res.TaskType, &res.Profile, &res.RunID, &res.AgentID, &res.Status, &metadataJSON, &summaryJSON, &res.ErrorMessage, &res.ExitCode, &res.ErrorCode, &res.ScenarioID, &res.ScenarioName, &res.CompletedAt, &res.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan task result: %w", err)
		}
		if len(metadataJSON) > 0 {
			_ = json.Unmarshal(metadataJSON, &res.Metadata)
		}
		if summaryJSON != nil {
			res.Summary = append([]byte(nil), summaryJSON...)
		}
		results = append(results, &res)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iter task result rows: %w", err)
	}
	return results, nil
}
