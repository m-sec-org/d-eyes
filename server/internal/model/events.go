package model

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// SystemEventRecord captures a normalized system event persisted by the server.
type SystemEventRecord struct {
	ID            uuid.UUID         `json:"id"`
	AgentID       uuid.UUID         `json:"agent_id"`
	AgentName     string            `json:"agent_name"`
	Collector     string            `json:"collector"`
	CollectorKind string            `json:"collector_kind"`
	EventType     string            `json:"event_type"`
	Source        string            `json:"source"`
	Priority      string            `json:"priority"`
	StorageTier   string            `json:"storage_tier"`
	Timestamp     time.Time         `json:"timestamp"`
	Sequence      uint64            `json:"sequence"`
	Payload       json.RawMessage   `json:"payload"`
	Metadata      map[string]string `json:"metadata"`
	Tags          map[string]string `json:"tags"`
	Raw           json.RawMessage   `json:"raw"`
	ReceivedAt    time.Time         `json:"received_at"`
}
