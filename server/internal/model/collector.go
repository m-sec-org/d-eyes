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
