package model

import (
	"time"

	"github.com/google/uuid"
)

// ThreatIntelSource enumerates external providers.
type ThreatIntelSource string

const (
	ThreatIntelSourceOpenTIP      ThreatIntelSource = "opentip"
	ThreatIntelSourceMetaDefender ThreatIntelSource = "metadefender"
)

// ThreatIntelJob represents a queued lookup/scan request.
type ThreatIntelJob struct {
	ID               uuid.UUID         `json:"id"`
	SampleID         uuid.UUID         `json:"sample_id"`
	Indicator        string            `json:"indicator"`
	Kind             string            `json:"kind"`
	Source           ThreatIntelSource `json:"source"`
	Status           string            `json:"status"`
	Payload          []byte            `json:"payload"`
	Attempt          int               `json:"attempt"`
	ErrorMsg         string            `json:"error_msg"`
	ErrorCode        string            `json:"error_code"`
	NextRunAt        time.Time         `json:"next_run_at"`
	CreatedAt        time.Time         `json:"created_at"`
	UpdatedAt        time.Time         `json:"updated_at"`
	LastTransitionAt time.Time         `json:"last_transition_at"`
	TaskRunID        uuid.UUID         `json:"task_run_id"`
	AgentID          uuid.UUID         `json:"agent_id"`
	ArtifactIDs      []uuid.UUID       `json:"artifact_ids"`
	Metadata         map[string]string `json:"metadata"`
	Summary          map[string]any    `json:"summary"`
}

// ThreatIntelVerdict stores normalized results from providers.
type ThreatIntelVerdict struct {
	ID             uuid.UUID         `json:"id"`
	Indicator      string            `json:"indicator"`
	Kind           string            `json:"kind"`
	Source         ThreatIntelSource `json:"source"`
	Classification string            `json:"classification"`
	Confidence     string            `json:"confidence"`
	Raw            []byte            `json:"raw"`
	RetrievedAt    time.Time         `json:"retrieved_at"`
	ExpiresAt      time.Time         `json:"expires_at"`
	JobID          uuid.UUID         `json:"job_id"`
	TaskRunID      uuid.UUID         `json:"task_run_id"`
	Metadata       map[string]string `json:"metadata"`
	CreatedAt      time.Time         `json:"created_at"`
}

// ThreatIntelSample tracks uploaded artifacts to be processed by the orchestrator.
type ThreatIntelSample struct {
	ID              uuid.UUID         `json:"id"`
	Indicator       string            `json:"indicator"`
	Hash            string            `json:"hash"`
	Filename        string            `json:"filename"`
	Size            int64             `json:"size"`
	Status          string            `json:"status"`
	ArtifactIDs     []uuid.UUID       `json:"artifact_ids"`
	ArtifactDetails []ArtifactDetail  `json:"artifact_details"`
	TaskRunID       uuid.UUID         `json:"task_run_id"`
	AgentID         uuid.UUID         `json:"agent_id"`
	Source          string            `json:"source"`
	Classification  string            `json:"classification"`
	JobStatuses     map[string]string `json:"job_statuses"`
	Metadata        map[string]string `json:"metadata"`
	LastError       string            `json:"last_error"`
	LastErrorCode   string            `json:"last_error_code"`
	CreatedAt       time.Time         `json:"created_at"`
	UpdatedAt       time.Time         `json:"updated_at"`
}

type ArtifactDetail struct {
	ID             uuid.UUID `json:"id"`
	SHA256         string    `json:"sha256"`
	MIMEType       string    `json:"mime_type"`
	QuarantinePath string    `json:"quarantine_path"`
}

const (
	// ThreatIntelJobStatusPending indicates the job is ready to be scheduled.
	ThreatIntelJobStatusPending = "pending"
	// ThreatIntelJobStatusRunning indicates the job is currently being processed.
	ThreatIntelJobStatusRunning = "running"
	// ThreatIntelJobStatusSucceeded indicates the job finished successfully.
	ThreatIntelJobStatusSucceeded = "succeeded"
	// ThreatIntelJobStatusFailed indicates the job failed with no more retries.
	ThreatIntelJobStatusFailed = "failed"
	// ThreatIntelJobStatusRetryBackoff indicates the job is waiting for retry.
	ThreatIntelJobStatusRetryBackoff = "retrying"

	// ThreatIntelSampleStatusPending indicates the sample is waiting for processing.
	ThreatIntelSampleStatusPending = "pending"
	// ThreatIntelSampleStatusScanning indicates at least one job is running.
	ThreatIntelSampleStatusScanning = "scanning"
	// ThreatIntelSampleStatusCompleted indicates all jobs finished successfully.
	ThreatIntelSampleStatusCompleted = "completed"
	// ThreatIntelSampleStatusFailed indicates the sample failed due to job errors.
	ThreatIntelSampleStatusFailed = "failed"
)
