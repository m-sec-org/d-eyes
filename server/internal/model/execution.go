package model

import "time"

// ExecutionSummary mirrors agent-side summary structure for task results.
type ExecutionSummary struct {
	Command         string         `json:"command"`
	Status          string         `json:"status"`
	DurationSeconds float64        `json:"duration_seconds"`
	Risks           map[string]int `json:"risks,omitempty"`
	Notes           []string       `json:"notes,omitempty"`
	Outputs         []OutputRecord `json:"outputs,omitempty"`
	ErrorMessage    string         `json:"error_message,omitempty"`
}

// OutputRecord represents generated report artifacts metadata.
type OutputRecord struct {
	Path        string `json:"path"`
	Type        string `json:"type,omitempty"`
	ContentType string `json:"content_type,omitempty"`
	Label       string `json:"label,omitempty"`
}

// ExecutionResult captures structured output returned from agents.
type ExecutionResult struct {
	Status     string            `json:"status"`
	Summary    ExecutionSummary  `json:"summary"`
	Artifacts  []OutputRecord    `json:"artifacts,omitempty"`
	Error      string            `json:"error,omitempty"`
	Metadata   map[string]string `json:"metadata,omitempty"`
	ExitCode   int32             `json:"exit_code,omitempty"`
	ErrorCode  string            `json:"error_code,omitempty"`
	ReportedAt time.Time         `json:"reported_at,omitempty"`
}
