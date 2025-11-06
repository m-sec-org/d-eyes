package model

import (
	"encoding/json"
	"time"
)

// TaskDescriptor 描述从 Server 下发的任务元信息。
type TaskDescriptor struct {
	ID       string            `json:"id"`
	Type     string            `json:"type"`
	Profile  string            `json:"profile,omitempty"`
	Metadata map[string]string `json:"metadata,omitempty"`
	Payload  json.RawMessage   `json:"payload,omitempty"`
	LeaseID  string            `json:"lease_id,omitempty"`
}

// ExecutionSummary 统一 Runner 返回的摘要。
type ExecutionSummary struct {
	Command         string         `json:"command"`
	Status          string         `json:"status"`
	DurationSeconds float64        `json:"duration_seconds"`
	Risks           map[string]int `json:"risks,omitempty"`
	Notes           []string       `json:"notes,omitempty"`
	Outputs         []OutputRecord `json:"outputs,omitempty"`
	ErrorMessage    string         `json:"error_message,omitempty"`
}

// OutputRecord 描述生成的输出文件或附件。
type OutputRecord struct {
	Path        string `json:"path"`
	Type        string `json:"type,omitempty"`
	ContentType string `json:"content_type,omitempty"`
	Label       string `json:"label,omitempty"`
}

// ExecutionResult 是任务运行后的结构化结果。
type ExecutionResult struct {
	Status     string            `json:"status"`
	Summary    ExecutionSummary  `json:"summary"`
	Artifacts  []OutputRecord    `json:"artifacts,omitempty"`
	Error      string            `json:"error,omitempty"`
	Metadata   map[string]string `json:"metadata,omitempty"`
	ExitCode   int32             `json:"exit_code,omitempty"`
	ErrorCode  string            `json:"error_code,omitempty"`
	ReportedAt time.Time         `json:"reported_at"`
}
