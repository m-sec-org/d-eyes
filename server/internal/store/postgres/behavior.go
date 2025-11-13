package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/m-sec-org/d-eyes/server/internal/model"
)

func (p *PostgresStore) SaveBehaviorMetric(ctx context.Context, metric *model.BehaviorMetric) error {
	if metric == nil {
		return fmt.Errorf("nil behavior metric")
	}
	if metric.ID == uuid.Nil {
		metric.ID = uuid.New()
	}
	if metric.CreatedAt.IsZero() {
		metric.CreatedAt = time.Now()
	}
	_, err := p.pool.Exec(ctx, `INSERT INTO behavior_metrics (
        id, agent_id, load, cpu_percent, latency_ms, running_tasks, blocked_actions, created_at)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		metric.ID, metric.AgentID, metric.Load, metric.CPUPercent, metric.LatencyMs,
		metric.RunningTasks, metric.BlockedActions, metric.CreatedAt)
	if err != nil {
		return fmt.Errorf("insert behavior metric: %w", err)
	}
	return nil
}

func (p *PostgresStore) SaveBehaviorEvent(ctx context.Context, event *model.BehaviorEvent) error {
	if event == nil {
		return fmt.Errorf("nil behavior event")
	}
	if event.ID == uuid.Nil {
		event.ID = uuid.New()
	}
	if event.CreatedAt.IsZero() {
		event.CreatedAt = time.Now()
	}
	metadataJSON, _ := json.Marshal(event.Metadata)
	_, err := p.pool.Exec(ctx, `INSERT INTO behavior_events (
        id, agent_id, task_id, metadata, created_at)
        VALUES ($1,$2,$3,$4,$5)`,
		event.ID, event.AgentID, event.TaskID, metadataJSON, event.CreatedAt)
	if err != nil {
		return fmt.Errorf("insert behavior event: %w", err)
	}
	return nil
}

func (p *PostgresStore) CreateAnomaly(ctx context.Context, anomaly *model.Anomaly) error {
	if anomaly == nil {
		return fmt.Errorf("nil anomaly")
	}
	if anomaly.ID == uuid.Nil {
		anomaly.ID = uuid.New()
	}
	now := time.Now()
	if anomaly.CreatedAt.IsZero() {
		anomaly.CreatedAt = now
	}
	if anomaly.UpdatedAt.IsZero() {
		anomaly.UpdatedAt = anomaly.CreatedAt
	}
	summaryJSON, _ := json.Marshal(anomaly.Summary)
	entitiesJSON, _ := json.Marshal(anomaly.Entities)
	var taskID interface{}
	if anomaly.TaskID != uuid.Nil {
		taskID = anomaly.TaskID
	}
	_, err := p.pool.Exec(ctx, `INSERT INTO anomalies (
        id, agent_id, task_id, ioc, entities, severity, score, summary, status, created_at, updated_at)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
		anomaly.ID, anomaly.AgentID, taskID, nullableString(anomaly.IOC), entitiesJSON, anomaly.Severity, anomaly.Score, summaryJSON, anomaly.Status, anomaly.CreatedAt, anomaly.UpdatedAt)
	if err != nil {
		return fmt.Errorf("insert anomaly: %w", err)
	}
	return nil
}

func (p *PostgresStore) ListAnomalies(ctx context.Context, limit int) ([]*model.Anomaly, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := p.pool.Query(ctx, `SELECT id, agent_id, task_id, ioc, entities, severity, score, summary, status, created_at, updated_at
        FROM anomalies ORDER BY created_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("list anomalies: %w", err)
	}
	defer rows.Close()
	var results []*model.Anomaly
	for rows.Next() {
		var a model.Anomaly
		var summaryJSON []byte
		var entitiesJSON []byte
		var taskID *uuid.UUID
		var ioc sql.NullString
		if err := rows.Scan(&a.ID, &a.AgentID, &taskID, &ioc, &entitiesJSON, &a.Severity, &a.Score, &summaryJSON, &a.Status, &a.CreatedAt, &a.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan anomaly: %w", err)
		}
		if taskID != nil {
			a.TaskID = *taskID
		}
		if ioc.Valid {
			a.IOC = ioc.String
		}
		if len(entitiesJSON) > 0 {
			_ = json.Unmarshal(entitiesJSON, &a.Entities)
		}
		if len(summaryJSON) > 0 {
			_ = json.Unmarshal(summaryJSON, &a.Summary)
		}
		results = append(results, &a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate anomalies: %w", err)
	}
	return results, nil
}

func (p *PostgresStore) GetAnomaly(ctx context.Context, id uuid.UUID) (*model.Anomaly, error) {
	row := p.pool.QueryRow(ctx, `SELECT id, agent_id, task_id, ioc, entities, severity, score, summary, status, created_at, updated_at
        FROM anomalies WHERE id = $1`, id)
	var a model.Anomaly
	var summaryJSON []byte
	var entitiesJSON []byte
	var taskID *uuid.UUID
	var ioc sql.NullString
	if err := row.Scan(&a.ID, &a.AgentID, &taskID, &ioc, &entitiesJSON, &a.Severity, &a.Score, &summaryJSON, &a.Status, &a.CreatedAt, &a.UpdatedAt); err != nil {
		return nil, fmt.Errorf("get anomaly: %w", err)
	}
	if taskID != nil {
		a.TaskID = *taskID
	}
	if ioc.Valid {
		a.IOC = ioc.String
	}
	if len(entitiesJSON) > 0 {
		_ = json.Unmarshal(entitiesJSON, &a.Entities)
	}
	if len(summaryJSON) > 0 {
		_ = json.Unmarshal(summaryJSON, &a.Summary)
	}
	return &a, nil
}

func (p *PostgresStore) ListAnomaliesByFilter(ctx context.Context, filter model.AnomalyFilter) ([]*model.Anomaly, error) {
	conditions := make([]string, 0, 4)
	args := make([]interface{}, 0, 5)
	argIdx := 1
	if filter.AgentID != nil {
		conditions = append(conditions, fmt.Sprintf("agent_id = $%d", argIdx))
		args = append(args, *filter.AgentID)
		argIdx++
	}
	if filter.TaskID != nil {
		conditions = append(conditions, fmt.Sprintf("task_id = $%d", argIdx))
		args = append(args, *filter.TaskID)
		argIdx++
	}
	if filter.IOC != "" {
		conditions = append(conditions, fmt.Sprintf("(ioc ILIKE $%d OR summary::text ILIKE $%d)", argIdx, argIdx))
		args = append(args, "%"+filter.IOC+"%")
		argIdx++
	}
	if len(filter.Status) > 0 {
		conditions = append(conditions, fmt.Sprintf("status = ANY($%d)", argIdx))
		args = append(args, filter.Status)
		argIdx++
	}
	if filter.MinScore > 0 {
		conditions = append(conditions, fmt.Sprintf("score >= $%d", argIdx))
		args = append(args, filter.MinScore)
		argIdx++
	}
	query := `SELECT id, agent_id, task_id, ioc, entities, severity, score, summary, status, created_at, updated_at FROM anomalies`
	if len(conditions) > 0 {
		query += " WHERE " + strings.Join(conditions, " AND ")
	}
	query += " ORDER BY created_at DESC"
	limit := filter.Limit
	if limit <= 0 {
		limit = 50
	}
	query += fmt.Sprintf(" LIMIT $%d", argIdx)
	args = append(args, limit)
	rows, err := p.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list anomalies with filter: %w", err)
	}
	defer rows.Close()
	var results []*model.Anomaly
	for rows.Next() {
		var a model.Anomaly
		var summaryJSON []byte
		var entitiesJSON []byte
		var taskID *uuid.UUID
		var ioc sql.NullString
		if err := rows.Scan(&a.ID, &a.AgentID, &taskID, &ioc, &entitiesJSON, &a.Severity, &a.Score, &summaryJSON, &a.Status, &a.CreatedAt, &a.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan anomaly filter: %w", err)
		}
		if taskID != nil {
			a.TaskID = *taskID
		}
		if ioc.Valid {
			a.IOC = ioc.String
		}
		if len(entitiesJSON) > 0 {
			_ = json.Unmarshal(entitiesJSON, &a.Entities)
		}
		if len(summaryJSON) > 0 {
			_ = json.Unmarshal(summaryJSON, &a.Summary)
		}
		results = append(results, &a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate anomaly filter: %w", err)
	}
	return results, nil
}

func (p *PostgresStore) SaveAnomalyGraph(ctx context.Context, anomalyID uuid.UUID, nodes []*model.BehaviorGraphNode, edges []*model.BehaviorGraphEdge) error {
	if anomalyID == uuid.Nil {
		return fmt.Errorf("anomalyID required")
	}
	if len(nodes) == 0 && len(edges) == 0 {
		return nil
	}
	batch := &pgx.Batch{}
	queued := 0
	now := time.Now()
	for _, node := range nodes {
		if node == nil {
			continue
		}
		if node.ID == uuid.Nil {
			node.ID = uuid.New()
		}
		if node.AnomalyID == uuid.Nil {
			node.AnomalyID = anomalyID
		}
		if node.CreatedAt.IsZero() {
			node.CreatedAt = now
		}
		propsJSON, _ := json.Marshal(node.Properties)
		batch.Queue(`INSERT INTO behavior_graph_nodes (id, anomaly_id, type, label, properties, created_at)
            VALUES ($1,$2,$3,$4,$5,$6)`,
			node.ID, node.AnomalyID, node.Type, node.Label, propsJSON, node.CreatedAt)
		queued++
	}
	for _, edge := range edges {
		if edge == nil {
			continue
		}
		if edge.ID == uuid.Nil {
			edge.ID = uuid.New()
		}
		if edge.AnomalyID == uuid.Nil {
			edge.AnomalyID = anomalyID
		}
		if edge.CreatedAt.IsZero() {
			edge.CreatedAt = now
		}
		propsJSON, _ := json.Marshal(edge.Properties)
		batch.Queue(`INSERT INTO behavior_graph_edges (id, anomaly_id, source_node, target_node, type, properties, created_at)
            VALUES ($1,$2,$3,$4,$5,$6,$7)`,
			edge.ID, edge.AnomalyID, edge.SourceNode, edge.TargetNode, edge.Type, propsJSON, edge.CreatedAt)
		queued++
	}
	br := p.pool.SendBatch(ctx, batch)
	defer br.Close()
	for i := 0; i < queued; i++ {
		if _, err := br.Exec(); err != nil {
			return fmt.Errorf("save anomaly graph: %w", err)
		}
	}
	return nil
}

func (p *PostgresStore) GetAnomalyGraph(ctx context.Context, anomalyID uuid.UUID) (*model.AnomalyGraph, error) {
	if anomalyID == uuid.Nil {
		return nil, fmt.Errorf("anomalyID required")
	}
	rows, err := p.pool.Query(ctx, `SELECT id, type, label, properties, created_at FROM behavior_graph_nodes WHERE anomaly_id = $1`, anomalyID)
	if err != nil {
		return nil, fmt.Errorf("select graph nodes: %w", err)
	}
	defer rows.Close()
	nodes := make([]*model.BehaviorGraphNode, 0)
	for rows.Next() {
		var node model.BehaviorGraphNode
		var propsJSON []byte
		if err := rows.Scan(&node.ID, &node.Type, &node.Label, &propsJSON, &node.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan graph node: %w", err)
		}
		node.AnomalyID = anomalyID
		if len(propsJSON) > 0 {
			_ = json.Unmarshal(propsJSON, &node.Properties)
		}
		nodes = append(nodes, &node)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate nodes: %w", err)
	}
	edgeRows, err := p.pool.Query(ctx, `SELECT id, source_node, target_node, type, properties, created_at FROM behavior_graph_edges WHERE anomaly_id = $1`, anomalyID)
	if err != nil {
		return nil, fmt.Errorf("select graph edges: %w", err)
	}
	defer edgeRows.Close()
	edges := make([]*model.BehaviorGraphEdge, 0)
	for edgeRows.Next() {
		var edge model.BehaviorGraphEdge
		var propsJSON []byte
		if err := edgeRows.Scan(&edge.ID, &edge.SourceNode, &edge.TargetNode, &edge.Type, &propsJSON, &edge.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan graph edge: %w", err)
		}
		edge.AnomalyID = anomalyID
		if len(propsJSON) > 0 {
			_ = json.Unmarshal(propsJSON, &edge.Properties)
		}
		edges = append(edges, &edge)
	}
	if err := edgeRows.Err(); err != nil {
		return nil, fmt.Errorf("iterate edges: %w", err)
	}
	return &model.AnomalyGraph{Nodes: nodes, Edges: edges}, nil
}

func nullableString(input string) interface{} {
	if strings.TrimSpace(input) == "" {
		return nil
	}
	return input
}
