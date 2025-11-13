package model

import (
	"time"

	"github.com/google/uuid"
)

type BehaviorMetric struct {
	ID             uuid.UUID `json:"id"`
	AgentID        uuid.UUID `json:"agent_id"`
	Load           float64   `json:"load"`
	CPUPercent     float64   `json:"cpu_percent"`
	LatencyMs      float64   `json:"latency_ms"`
	RunningTasks   []string  `json:"running_tasks,omitempty"`
	BlockedActions []string  `json:"blocked_actions,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
}

type BehaviorEvent struct {
	ID        uuid.UUID         `json:"id"`
	AgentID   uuid.UUID         `json:"agent_id"`
	TaskID    uuid.UUID         `json:"task_id"`
	Metadata  map[string]string `json:"metadata,omitempty"`
	CreatedAt time.Time         `json:"created_at"`
}

type Anomaly struct {
	ID        uuid.UUID              `json:"id"`
	AgentID   uuid.UUID              `json:"agent_id"`
	TaskID    uuid.UUID              `json:"task_id,omitempty"`
	IOC       string                 `json:"ioc,omitempty"`
	Entities  []string               `json:"entities,omitempty"`
	Severity  string                 `json:"severity"`
	Score     float64                `json:"score"`
	Summary   map[string]interface{} `json:"summary,omitempty"`
	Status    string                 `json:"status"`
	CreatedAt time.Time              `json:"created_at"`
	UpdatedAt time.Time              `json:"updated_at"`
}

type BehaviorGraphNode struct {
	ID         uuid.UUID              `json:"id"`
	AnomalyID  uuid.UUID              `json:"anomaly_id"`
	Type       string                 `json:"type"`
	Label      string                 `json:"label,omitempty"`
	Properties map[string]interface{} `json:"properties,omitempty"`
	CreatedAt  time.Time              `json:"created_at"`
}

type BehaviorGraphEdge struct {
	ID         uuid.UUID              `json:"id"`
	AnomalyID  uuid.UUID              `json:"anomaly_id"`
	SourceNode uuid.UUID              `json:"source_node"`
	TargetNode uuid.UUID              `json:"target_node"`
	Type       string                 `json:"type"`
	Properties map[string]interface{} `json:"properties,omitempty"`
	CreatedAt  time.Time              `json:"created_at"`
}

type AnomalyGraph struct {
	Nodes []*BehaviorGraphNode `json:"nodes"`
	Edges []*BehaviorGraphEdge `json:"edges"`
}

type AnomalyFilter struct {
	AgentID  *uuid.UUID
	TaskID   *uuid.UUID
	IOC      string
	Status   []string
	MinScore float64
	Limit    int
}
