package behavior

import (
	"time"

	"github.com/google/uuid"
)

// HeartbeatMetric describes augmented heartbeat payloads.
type HeartbeatMetric struct {
	AgentID        uuid.UUID
	Timestamp      time.Time
	Load           float64
	RunningTasks   []string
	LatencyMs      float64
	CPUPercent     float64
	BlockedActions []string
}

// TaskTelemetry captures process/network telemetry from task execution.
type TaskTelemetry struct {
	AgentID    uuid.UUID
	TaskID     uuid.UUID
	Metadata   map[string]string
	ReceivedAt time.Time
}
