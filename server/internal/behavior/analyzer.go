package behavior

import (
	"context"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"github.com/m-sec-org/d-eyes/server/internal/config"
	"github.com/m-sec-org/d-eyes/server/internal/model"
	"github.com/m-sec-org/d-eyes/server/internal/store"
)

// Analyzer ingests telemetry and produces anomalies.
type Analyzer struct {
	store store.Store
	log   *slog.Logger
	cfg   config.BehaviorConfig
	hub   *Hub
}

func NewAnalyzer(cfg config.BehaviorConfig, st store.Store, logger *slog.Logger, hub *Hub) *Analyzer {
	if !cfg.Enabled {
		return nil
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Analyzer{store: st, log: logger, cfg: cfg, hub: hub}
}

func (a *Analyzer) Enabled() bool {
	return a != nil && a.store != nil
}

func (a *Analyzer) ProcessHeartbeat(ctx context.Context, metric HeartbeatMetric) {
	if !a.Enabled() {
		return
	}
	rec := &model.BehaviorMetric{
		AgentID:        metric.AgentID,
		Load:           metric.Load,
		CPUPercent:     metric.CPUPercent,
		LatencyMs:      metric.LatencyMs,
		RunningTasks:   append([]string(nil), metric.RunningTasks...),
		BlockedActions: append([]string(nil), metric.BlockedActions...),
		CreatedAt:      metric.Timestamp,
	}
	if err := a.store.SaveBehaviorMetric(ctx, rec); err != nil {
		a.log.Debug("save behavior metric", "error", err)
	}
	threshold := a.cfg.AnomalyCPUThreshold
	if threshold <= 0 {
		threshold = 90
	}
	if metric.CPUPercent >= threshold || len(metric.BlockedActions) > 0 {
		a.raiseAnomaly(ctx, metric.AgentID, "high_cpu", metric.CPUPercent, map[string]interface{}{
			"cpu_percent":     metric.CPUPercent,
			"blocked_actions": metric.BlockedActions,
		})
	}
}

func (a *Analyzer) ProcessTaskTelemetry(ctx context.Context, payload TaskTelemetry) {
	if !a.Enabled() {
		return
	}
	event := &model.BehaviorEvent{
		AgentID:   payload.AgentID,
		TaskID:    payload.TaskID,
		Metadata:  payload.Metadata,
		CreatedAt: payload.ReceivedAt,
	}
	if err := a.store.SaveBehaviorEvent(ctx, event); err != nil {
		a.log.Debug("save behavior event", "error", err)
	}
	if len(payload.Metadata) > 0 {
		a.raiseAnomaly(ctx, payload.AgentID, "telemetry_observed", 0, map[string]interface{}{
			"keys":    mapKeys(payload.Metadata),
			"task_id": payload.TaskID.String(),
		})
	}
}

func (a *Analyzer) raiseAnomaly(ctx context.Context, agentID uuid.UUID, reason string, score float64, summary map[string]interface{}) {
	anomaly := &model.Anomaly{
		AgentID:   agentID,
		Severity:  severityFromScore(score),
		Score:     score,
		Summary:   summary,
		Status:    "open",
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	if anomaly.Summary == nil {
		anomaly.Summary = make(map[string]interface{})
	}
	anomaly.Summary["reason"] = reason
	if err := a.store.CreateAnomaly(ctx, anomaly); err != nil {
		a.log.Debug("create anomaly", "error", err)
		return
	}
	a.emitEvent(anomaly)
}

func (a *Analyzer) emitEvent(anomaly *model.Anomaly) {
	if a == nil || a.hub == nil || anomaly == nil {
		return
	}
	a.hub.Emit("created", anomaly, nil)
}

func mapKeys(m map[string]string) []string {
	if len(m) == 0 {
		return nil
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

func severityFromScore(score float64) string {
	switch {
	case score >= 90:
		return "critical"
	case score >= 70:
		return "high"
	case score >= 40:
		return "medium"
	default:
		return "low"
	}
}
