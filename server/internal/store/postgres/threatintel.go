package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/m-sec-org/d-eyes/server/internal/model"
	"github.com/m-sec-org/d-eyes/server/internal/store"
)

func (p *PostgresStore) CreateThreatIntelSample(ctx context.Context, sample *model.ThreatIntelSample) error {
	if sample == nil {
		return fmt.Errorf("nil threat intel sample")
	}
	if sample.ID == uuid.Nil {
		sample.ID = uuid.New()
	}
	now := time.Now()
	if sample.CreatedAt.IsZero() {
		sample.CreatedAt = now
	}
	sample.UpdatedAt = now
	if sample.Indicator == "" {
		sample.Indicator = sample.Hash
	}
	metaJSON, _ := json.Marshal(sample.Metadata)
	detailsJSON, _ := json.Marshal(sample.ArtifactDetails)
	_, err := p.pool.Exec(ctx, `
        INSERT INTO threat_intel_samples
            (id, indicator, hash, filename, size, status, artifact_ids, artifact_details,
             task_run_id, agent_id, source, classification, metadata, last_error, last_error_code, created_at, updated_at)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)
    `,
		sample.ID, sample.Indicator, sample.Hash, sample.Filename, sample.Size, sample.Status, sample.ArtifactIDs,
		bytesOrNull(detailsJSON), sample.TaskRunID, sample.AgentID, sample.Source, sample.Classification,
		metaJSON, sample.LastError, sample.LastErrorCode, sample.CreatedAt, sample.UpdatedAt)
	if err != nil {
		return fmt.Errorf("insert threat intel sample: %w", err)
	}
	return nil
}

func (p *PostgresStore) UpdateThreatIntelSampleStatus(ctx context.Context, sampleID uuid.UUID, status, lastError, lastErrorCode string, metadata map[string]string) error {
	var metaJSON []byte
	if metadata != nil {
		metaJSON, _ = json.Marshal(metadata)
	}
	_, err := p.pool.Exec(ctx, `
        UPDATE threat_intel_samples
           SET status = CASE WHEN $2 <> '' THEN $2 ELSE status END,
               last_error = $3,
               metadata = COALESCE($4, metadata),
               last_error_code = CASE WHEN $5 <> '' THEN $5 ELSE last_error_code END,
               updated_at = NOW()
         WHERE id = $1
    `, sampleID, status, lastError, bytesOrNull(metaJSON), lastErrorCode)
	if err != nil {
		return fmt.Errorf("update threat intel sample: %w", err)
	}
	return nil
}

func (p *PostgresStore) GetThreatIntelSample(ctx context.Context, sampleID uuid.UUID) (*model.ThreatIntelSample, error) {
	row := p.pool.QueryRow(ctx, `
        SELECT id, indicator, hash, filename, size, status, artifact_ids, artifact_details,
               task_run_id, agent_id, source, classification, metadata, last_error, last_error_code, created_at, updated_at
          FROM threat_intel_samples
         WHERE id = $1
    `, sampleID)
	var sample model.ThreatIntelSample
	var metaJSON, detailsJSON []byte
	if err := row.Scan(&sample.ID, &sample.Indicator, &sample.Hash, &sample.Filename, &sample.Size, &sample.Status,
		&sample.ArtifactIDs, &detailsJSON, &sample.TaskRunID, &sample.AgentID, &sample.Source, &sample.Classification,
		&metaJSON, &sample.LastError, &sample.LastErrorCode, &sample.CreatedAt, &sample.UpdatedAt); err != nil {
		if err == pgx.ErrNoRows {
			return nil, store.ErrNotFound
		}
		return nil, fmt.Errorf("get threat intel sample: %w", err)
	}
	if len(metaJSON) > 0 {
		_ = json.Unmarshal(metaJSON, &sample.Metadata)
	}
	if len(detailsJSON) > 0 {
		_ = json.Unmarshal(detailsJSON, &sample.ArtifactDetails)
	}
	return &sample, nil
}

func (p *PostgresStore) ListThreatIntelJobsBySample(ctx context.Context, sampleID uuid.UUID) ([]*model.ThreatIntelJob, error) {
	rows, err := p.pool.Query(ctx, `
        SELECT id, sample_id, indicator, kind, source, status, payload, attempt, error_msg, error_code, next_run_at,
               created_at, updated_at, last_transition_at, task_run_id, agent_id, artifact_ids, metadata, summary
          FROM threat_intel_jobs
         WHERE sample_id = $1
         ORDER BY created_at ASC
    `, sampleID)
	if err != nil {
		return nil, fmt.Errorf("list threat intel jobs: %w", err)
	}
	defer rows.Close()
	return scanThreatIntelJobs(rows)
}

func (p *PostgresStore) InsertThreatIntelJob(ctx context.Context, job *model.ThreatIntelJob) error {
	if job == nil {
		return fmt.Errorf("nil threat intel job")
	}
	if job.ID == uuid.Nil {
		job.ID = uuid.New()
	}
	now := time.Now()
	if job.CreatedAt.IsZero() {
		job.CreatedAt = now
	}
	job.UpdatedAt = now
	if job.LastTransitionAt.IsZero() {
		job.LastTransitionAt = job.CreatedAt
	}
	if job.Status == "" {
		job.Status = model.ThreatIntelJobStatusPending
	}
	metaJSON, _ := json.Marshal(job.Metadata)
	summaryJSON, _ := json.Marshal(job.Summary)
	_, err := p.pool.Exec(ctx, `
        INSERT INTO threat_intel_jobs
            (id, sample_id, indicator, kind, source, status, payload, attempt, error_msg, error_code, next_run_at,
             created_at, updated_at, last_transition_at, task_run_id, agent_id, artifact_ids, metadata, summary)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)
    `,
		job.ID, job.SampleID, job.Indicator, job.Kind, job.Source, job.Status, job.Payload, job.Attempt,
		job.ErrorMsg, job.ErrorCode, nullTime(job.NextRunAt), job.CreatedAt, job.UpdatedAt, job.LastTransitionAt,
		job.TaskRunID, job.AgentID, job.ArtifactIDs, bytesOrNull(metaJSON), bytesOrNull(summaryJSON))
	if err != nil {
		return fmt.Errorf("insert threat intel job: %w", err)
	}
	return nil
}

func (p *PostgresStore) LeaseThreatIntelJobs(ctx context.Context, limit int) ([]*model.ThreatIntelJob, error) {
	if limit <= 0 {
		limit = 10
	}
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin lease threat intel jobs: %w", err)
	}
	defer func() {
		_ = tx.Rollback(ctx)
	}()
	rows, err := tx.Query(ctx, `
        SELECT id, sample_id, indicator, kind, source, status, payload, attempt, error_msg, error_code, next_run_at,
               created_at, updated_at, last_transition_at, task_run_id, agent_id, artifact_ids, metadata, summary
          FROM threat_intel_jobs
         WHERE status IN ($1,$2)
           AND (next_run_at IS NULL OR next_run_at <= NOW())
         ORDER BY created_at ASC
         LIMIT $3
         FOR UPDATE SKIP LOCKED
    `, model.ThreatIntelJobStatusPending, model.ThreatIntelJobStatusRetryBackoff, limit)
	if err != nil {
		return nil, fmt.Errorf("lease threat intel jobs: %w", err)
	}
	jobs, err := scanThreatIntelJobs(rows)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	for i := range jobs {
		jobs[i].Status = model.ThreatIntelJobStatusRunning
		jobs[i].Attempt++
		jobs[i].UpdatedAt = now
		if _, err := tx.Exec(ctx, `
            UPDATE threat_intel_jobs
               SET status=$2, attempt=$3, updated_at=$4, last_transition_at=$4
             WHERE id=$1
        `, jobs[i].ID, jobs[i].Status, jobs[i].Attempt, jobs[i].UpdatedAt); err != nil {
			return nil, fmt.Errorf("mark threat intel job running: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit lease threat intel jobs: %w", err)
	}
	return jobs, nil
}

func (p *PostgresStore) ListThreatIntelJobs(ctx context.Context, limit int) ([]*model.ThreatIntelJob, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := p.pool.Query(ctx, `
        SELECT id, sample_id, indicator, kind, source, status, payload, attempt, error_msg, error_code, next_run_at,
               created_at, updated_at, last_transition_at, task_run_id, agent_id, artifact_ids, metadata, summary
          FROM threat_intel_jobs
         ORDER BY created_at DESC
         LIMIT $1
    `, limit)
	if err != nil {
		return nil, fmt.Errorf("list threat intel jobs: %w", err)
	}
	return scanThreatIntelJobs(rows)
}

func (p *PostgresStore) UpdateThreatIntelJobStatus(ctx context.Context, jobID uuid.UUID, status string, nextRunAt time.Time, errMsg, errorCode string, metadata map[string]string) error {
	var metaJSON []byte
	if metadata != nil {
		metaJSON, _ = json.Marshal(metadata)
	}
	_, err := p.pool.Exec(ctx, `
        UPDATE threat_intel_jobs
           SET status = CASE WHEN $2 <> '' THEN $2 ELSE status END,
               next_run_at = $3,
               error_msg = $4,
               error_code = CASE WHEN $5 <> '' THEN $5 ELSE error_code END,
               metadata = COALESCE($6, metadata),
               updated_at = NOW(),
               last_transition_at = CASE WHEN $2 <> '' THEN NOW() ELSE last_transition_at END
         WHERE id = $1
    `, jobID, status, nullTime(nextRunAt), errMsg, errorCode, bytesOrNull(metaJSON))
	if err != nil {
		return fmt.Errorf("update threat intel job: %w", err)
	}
	return nil
}

func (p *PostgresStore) InsertThreatIntelVerdict(ctx context.Context, verdict *model.ThreatIntelVerdict) error {
	if verdict == nil {
		return fmt.Errorf("nil threat intel verdict")
	}
	if verdict.ID == uuid.Nil {
		verdict.ID = uuid.New()
	}
	if verdict.CreatedAt.IsZero() {
		verdict.CreatedAt = time.Now()
	}
	metaJSON, _ := json.Marshal(verdict.Metadata)
	_, err := p.pool.Exec(ctx, `
	        INSERT INTO threat_intel_verdicts
	            (id, indicator, kind, source, classification, confidence, raw, retrieved_at, expires_at, job_id, task_run_id, metadata, created_at)
	        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
	    `,
		verdict.ID, verdict.Indicator, verdict.Kind, verdict.Source, verdict.Classification, verdict.Confidence,
		verdict.Raw, verdict.RetrievedAt, verdict.ExpiresAt, verdict.JobID, verdict.TaskRunID, bytesOrNull(metaJSON), verdict.CreatedAt)
	if err != nil {
		return fmt.Errorf("insert threat intel verdict: %w", err)
	}
	return nil
}

func (p *PostgresStore) ListThreatIntelVerdicts(ctx context.Context, indicator string, limit int) ([]*model.ThreatIntelVerdict, error) {
	if limit <= 0 {
		limit = 50
	}
	var rows pgx.Rows
	var err error
	indicator = strings.TrimSpace(indicator)
	if indicator != "" {
		rows, err = p.pool.Query(ctx, `
            SELECT id, indicator, kind, source, classification, confidence, raw, retrieved_at, expires_at, job_id, task_run_id, metadata, created_at
              FROM threat_intel_verdicts
             WHERE indicator = $1
               AND (expires_at IS NULL OR expires_at > NOW())
             ORDER BY retrieved_at DESC, id DESC
             LIMIT $2
        `, indicator, limit)
	} else {
		rows, err = p.pool.Query(ctx, `
            SELECT id, indicator, kind, source, classification, confidence, raw, retrieved_at, expires_at, job_id, task_run_id, metadata, created_at
              FROM threat_intel_verdicts
             WHERE expires_at IS NULL OR expires_at > NOW()
             ORDER BY retrieved_at DESC, id DESC
             LIMIT $1
        `, limit)
	}
	if err != nil {
		return nil, fmt.Errorf("list threat intel verdicts: %w", err)
	}
	defer rows.Close()
	results := make([]*model.ThreatIntelVerdict, 0, limit)
	for rows.Next() {
		var v model.ThreatIntelVerdict
		var metaJSON []byte
		if err := rows.Scan(&v.ID, &v.Indicator, &v.Kind, &v.Source, &v.Classification, &v.Confidence,
			&v.Raw, &v.RetrievedAt, &v.ExpiresAt, &v.JobID, &v.TaskRunID, &metaJSON, &v.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan threat intel verdict: %w", err)
		}
		if len(metaJSON) > 0 {
			_ = json.Unmarshal(metaJSON, &v.Metadata)
		}
		results = append(results, &v)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate threat intel verdicts: %w", err)
	}
	return results, nil
}

func (p *PostgresStore) CountThreatIntelJobs(ctx context.Context, statuses []string) (int64, error) {
	query := `SELECT COUNT(*) FROM threat_intel_jobs`
	var row pgx.Row
	if len(statuses) > 0 {
		query += ` WHERE status = ANY($1)`
		row = p.pool.QueryRow(ctx, query, statuses)
	} else {
		row = p.pool.QueryRow(ctx, query)
	}
	var count int64
	if err := row.Scan(&count); err != nil {
		return 0, fmt.Errorf("count threat intel jobs: %w", err)
	}
	return count, nil
}

func scanThreatIntelJobs(rows pgx.Rows) ([]*model.ThreatIntelJob, error) {
	defer rows.Close()
	results := make([]*model.ThreatIntelJob, 0)
	for rows.Next() {
		var job model.ThreatIntelJob
		var metaJSON, summaryJSON []byte
		if err := rows.Scan(&job.ID, &job.SampleID, &job.Indicator, &job.Kind, &job.Source, &job.Status,
			&job.Payload, &job.Attempt, &job.ErrorMsg, &job.ErrorCode, &job.NextRunAt, &job.CreatedAt, &job.UpdatedAt,
			&job.LastTransitionAt, &job.TaskRunID, &job.AgentID, &job.ArtifactIDs, &metaJSON, &summaryJSON); err != nil {
			return nil, fmt.Errorf("scan threat intel job: %w", err)
		}
		if len(metaJSON) > 0 {
			_ = json.Unmarshal(metaJSON, &job.Metadata)
		}
		if len(summaryJSON) > 0 {
			_ = json.Unmarshal(summaryJSON, &job.Summary)
		}
		results = append(results, &job)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate threat intel job rows: %w", err)
	}
	return results, nil
}

func bytesOrNull(b []byte) any {
	if len(b) == 0 {
		return nil
	}
	return b
}

func nullTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t
}
