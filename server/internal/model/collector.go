package model

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// CollectorConfigSnapshot captures the latest collector configuration issued to an agent.
type CollectorConfigSnapshot struct {
	AgentID   uuid.UUID       `json:"agent_id"`
	Version   int64           `json:"version"`
	Config    json.RawMessage `json:"config"`
	UpdatedBy string          `json:"updated_by"`
	UpdatedAt time.Time       `json:"updated_at"`
}

// CollectorStatusSnapshot captures the last-known runtime status per agent.
type CollectorStatusSnapshot struct {
	AgentID   uuid.UUID         `json:"agent_id"`
	AgentName string            `json:"agent_name"`
	Version   int64             `json:"version"`
	State     string            `json:"state"`
	LastError string            `json:"last_error"`
	Stats     map[string]any    `json:"stats"`
	Metadata  map[string]string `json:"metadata"`
	UpdatedAt time.Time         `json:"updated_at"`
}

// CollectorRolloutStatus captures rollout lifecycle states.
type CollectorRolloutStatus string

const (
	CollectorRolloutStatusPending     CollectorRolloutStatus = "pending"
	CollectorRolloutStatusInProgress  CollectorRolloutStatus = "in_progress"
	CollectorRolloutStatusCompleted   CollectorRolloutStatus = "completed"
	CollectorRolloutStatusFailed      CollectorRolloutStatus = "failed"
	CollectorRolloutStatusCanceled    CollectorRolloutStatus = "canceled"
	CollectorRolloutStatusRollingBack CollectorRolloutStatus = "rolling_back"
	CollectorRolloutStatusRolledBack  CollectorRolloutStatus = "rolled_back"
)

// CollectorRolloutTargetState captures per-agent acknowledgement state.
type CollectorRolloutTargetState string

const (
	CollectorRolloutTargetStatePending    CollectorRolloutTargetState = "pending"
	CollectorRolloutTargetStateAcked      CollectorRolloutTargetState = "acked"
	CollectorRolloutTargetStateFailed     CollectorRolloutTargetState = "failed"
	CollectorRolloutTargetStateRolledBack CollectorRolloutTargetState = "rolled_back"
)

// CollectorRollout tracks a config push across agents.
type CollectorRollout struct {
	ID                 uuid.UUID              `json:"id"`
	Name               string                 `json:"name"`
	Description        string                 `json:"description,omitempty"`
	Selector           map[string]string      `json:"selector,omitempty"`
	Status             CollectorRolloutStatus `json:"status"`
	Config             json.RawMessage        `json:"config"`
	Version            int64                  `json:"version"`
	Strategy           string                 `json:"strategy,omitempty"`
	CreatedBy          string                 `json:"created_by"`
	CreatedAt          time.Time              `json:"created_at"`
	StartedAt          time.Time              `json:"started_at"`
	CompletedAt        *time.Time             `json:"completed_at,omitempty"`
	RolledBackAt       *time.Time             `json:"rolled_back_at,omitempty"`
	RollbackReason     string                 `json:"rollback_reason,omitempty"`
	GracePeriodSeconds int64                  `json:"grace_period_seconds"`
	TargetCount        int                    `json:"target_count"`
	AckCount           int                    `json:"ack_count"`
	FailedCount        int                    `json:"failed_count"`
	Notes              string                 `json:"notes,omitempty"`
}

// CollectorRolloutTarget captures per-agent rollout metadata.
type CollectorRolloutTarget struct {
	RolloutID       uuid.UUID                   `json:"rollout_id"`
	AgentID         uuid.UUID                   `json:"agent_id"`
	AgentName       string                      `json:"agent_name"`
	DesiredVersion  int64                       `json:"desired_version"`
	PreviousVersion int64                       `json:"previous_version"`
	PreviousConfig  json.RawMessage             `json:"-"`
	State           CollectorRolloutTargetState `json:"state"`
	AckedAt         *time.Time                  `json:"acked_at,omitempty"`
	LastHeartbeat   time.Time                   `json:"last_heartbeat,omitempty"`
	LastError       string                      `json:"last_error,omitempty"`
	CreatedAt       time.Time                   `json:"created_at"`
	UpdatedAt       time.Time                   `json:"updated_at"`
	Metadata        map[string]string           `json:"metadata,omitempty"`
}
