package threatintel

import (
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/m-sec-org/d-eyes/server/internal/model"
)

// SampleSubmission captures the information required to enqueue a sample-based scan.
type SampleSubmission struct {
	ArtifactIDs []uuid.UUID
	Hash        string
	Filename    string
	Size        int64
	TaskRunID   uuid.UUID
	AgentID     uuid.UUID
	Metadata    map[string]string
}

// LookupRequest represents an indicator lookup request originating from API/CLI.
type LookupRequest struct {
	Indicator string
	Kind      string
	Sources   []model.ThreatIntelSource
	Metadata  map[string]string
	TaskRunID uuid.UUID
	AgentID   uuid.UUID
	Force     bool
}

// Event is emitted onto the SSE stream for front-end consumption.
type Event struct {
	Type           string            `json:"event"`
	SampleID       string            `json:"sample_id,omitempty"`
	JobID          string            `json:"job_id,omitempty"`
	Indicator      string            `json:"indicator,omitempty"`
	Source         string            `json:"source,omitempty"`
	Status         string            `json:"status,omitempty"`
	Classification string            `json:"classification,omitempty"`
	Confidence     string            `json:"confidence,omitempty"`
	ArtifactIDs    []string          `json:"artifact_ids,omitempty"`
	ArtifactTypes  []string          `json:"artifact_types,omitempty"`
	ErrorCode      string            `json:"error_code,omitempty"`
	Message        string            `json:"message,omitempty"`
	Metadata       map[string]string `json:"metadata,omitempty"`
	Timestamp      time.Time         `json:"timestamp"`
}

// RetryableError instructs the orchestrator to retry the job after a backoff.
type RetryableError struct {
	Err        error
	RetryAfter time.Duration
}

func (e *RetryableError) Error() string {
	if e == nil {
		return "<nil>"
	}
	if e.Err != nil {
		return e.Err.Error()
	}
	return "retryable error"
}

func (e *RetryableError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// ErrUnsupportedSource indicates a job references an unknown provider.
var ErrUnsupportedSource = errors.New("threatintel: unsupported source")
