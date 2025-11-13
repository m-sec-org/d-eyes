package behavior

import (
	"context"
	"encoding/json"
	"log/slog"

	redis "github.com/redis/go-redis/v9"

	"github.com/m-sec-org/d-eyes/server/internal/config"
)

// Recorder persists behavior telemetry downstream (Redis Streams / logs).
type Recorder struct {
	log             *slog.Logger
	redis           *redis.Client
	heartbeatStream string
	taskStream      string
}

// NewRecorder constructs a recorder based on behavior + redis config.
func NewRecorder(cfg config.BehaviorConfig, redisCfg config.RedisConfig, logger *slog.Logger) (*Recorder, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	streamHB := cfg.HeartbeatStream
	if streamHB == "" {
		streamHB = "behavior.heartbeats"
	}
	streamTask := cfg.EventStream
	if streamTask == "" {
		streamTask = "behavior.events"
	}
	var client *redis.Client
	if redisCfg.Enabled {
		client = redis.NewClient(&redis.Options{
			Addr:         redisCfg.Addr,
			Password:     redisCfg.Password,
			DB:           redisCfg.DB,
			DialTimeout:  redisCfg.DialTimeout,
			ReadTimeout:  redisCfg.ReadTimeout,
			WriteTimeout: redisCfg.WriteTimeout,
		})
		if err := client.Ping(context.Background()).Err(); err != nil {
			return nil, err
		}
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Recorder{
		log:             logger,
		redis:           client,
		heartbeatStream: streamHB,
		taskStream:      streamTask,
	}, nil
}

// RecordHeartbeat forwards heartbeat metrics to downstream stream/log.
func (r *Recorder) RecordHeartbeat(ctx context.Context, metric HeartbeatMetric) {
	if r == nil {
		return
	}
	payload := map[string]any{
		"agent_id":        metric.AgentID.String(),
		"timestamp":       metric.Timestamp.Unix(),
		"load":            metric.Load,
		"tasks":           metric.RunningTasks,
		"latency_ms":      metric.LatencyMs,
		"cpu_percent":     metric.CPUPercent,
		"blocked_actions": metric.BlockedActions,
	}
	r.publish(ctx, r.heartbeatStream, payload)
}

// RecordTaskTelemetry publishes task-level telemetry metadata.
func (r *Recorder) RecordTaskTelemetry(ctx context.Context, telemetry TaskTelemetry) {
	if r == nil {
		return
	}
	payload := map[string]any{
		"agent_id":  telemetry.AgentID.String(),
		"task_id":   telemetry.TaskID.String(),
		"metadata":  telemetry.Metadata,
		"timestamp": telemetry.ReceivedAt.Unix(),
	}
	r.publish(ctx, r.taskStream, payload)
}

func (r *Recorder) publish(ctx context.Context, stream string, payload map[string]any) {
	if stream == "" {
		return
	}
	if r.redis != nil {
		_ = r.redis.XAdd(ctx, &redis.XAddArgs{Stream: stream, Values: payload}).Err()
		return
	}
	data, err := json.Marshal(payload)
	if err != nil {
		r.log.Debug("behavior recorder marshal error", "error", err)
		return
	}
	r.log.Debug("behavior telemetry", "stream", stream, "payload", string(data))
}

// Enabled reports whether recorder is active.
func (r *Recorder) Enabled() bool {
	return r != nil
}
