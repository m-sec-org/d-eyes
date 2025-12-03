package model

import (
	"time"

	"github.com/google/uuid"
)

type AgentStatus string

type TaskStatus string

type TaskType string

type Agent struct {
	ID            uuid.UUID         `json:"id"`
	Name          string            `json:"name"`
	Labels        map[string]string `json:"labels"`
	Platform      string            `json:"platform"`
	Version       string            `json:"version"`
	Capabilities  []string          `json:"capabilities"`
	Status        AgentStatus       `json:"status"`
	LastHeartbeat time.Time         `json:"lastHeartbeat"`
	Load          float64           `json:"load"`
	RunningTasks  []string          `json:"runningTasks,omitempty"`
	Metadata      map[string]string `json:"metadata,omitempty"`
	CreatedAt     time.Time         `json:"createdAt"`
	UpdatedAt     time.Time         `json:"updatedAt"`
}

type Task struct {
	ID         uuid.UUID         `json:"id"`
	Type       TaskType          `json:"type"`
	Profile    string            `json:"profile"`
	Priority   int               `json:"priority"`
	Payload    []byte            `json:"payload"` // JSON blob
	Status     TaskStatus        `json:"status"`
	RetryCount int               `json:"retryCount"`
	Metadata   map[string]string `json:"metadata"`
	CreatedBy  string            `json:"createdBy"`
	CreatedAt  time.Time         `json:"createdAt"`
	UpdatedAt  time.Time         `json:"updatedAt"`
}

type TaskRun struct {
	ID            uuid.UUID         `json:"id"`
	TaskID        uuid.UUID         `json:"taskId"`
	TaskType      TaskType          `json:"taskType"`
	AgentID       uuid.UUID         `json:"agentId"`
	LeaseID       uuid.UUID         `json:"leaseId"`
	LeaseExpires  time.Time         `json:"leaseExpires"`
	StartedAt     *time.Time        `json:"startedAt"`
	FinishedAt    *time.Time        `json:"finishedAt"`
	Status        TaskStatus        `json:"status"`
	ErrorMessage  string            `json:"errorMessage"`
	Summary       []byte            `json:"summary"`
	Metadata      map[string]string `json:"metadata"`
	ExitCode      int32             `json:"exitCode"`
	ErrorCode     string            `json:"errorCode"`
	ExpiresAt     time.Time         `json:"expiresAt"`
	RetrySequence int               `json:"retrySequence"`
}

type Artifact struct {
	ID        uuid.UUID `json:"id"`
	TaskRunID uuid.UUID `json:"taskRunId"`
	Name      string    `json:"name"`
	MIMEType  string    `json:"mimeType"`
	Blob      []byte    `json:"blob"`
}

type TaskResult struct {
	ID           uuid.UUID         `json:"id"`
	TaskID       uuid.UUID         `json:"taskId"`
	TaskType     TaskType          `json:"taskType"`
	Profile      string            `json:"profile"`
	RunID        uuid.UUID         `json:"runId"`
	AgentID      uuid.UUID         `json:"agentId"`
	Status       TaskStatus        `json:"status"`
	Metadata     map[string]string `json:"metadata"`
	Summary      []byte            `json:"summary"`
	ErrorMessage string            `json:"errorMessage"`
	ExitCode     int32             `json:"exitCode"`
	ErrorCode    string            `json:"errorCode"`
	ScenarioID   string            `json:"scenarioId"`
	ScenarioName string            `json:"scenarioName"`
	CompletedAt  time.Time         `json:"completedAt"`
	CreatedAt    time.Time         `json:"createdAt"`
}

type TaskView struct {
	ID        uuid.UUID              `json:"id"`
	Name      string                 `json:"name"`
	Owner     string                 `json:"owner"`
	Filters   map[string]interface{} `json:"filters"`
	PageSize  int                    `json:"pageSize"`
	IsDefault bool                   `json:"isDefault"`
	CreatedAt time.Time              `json:"createdAt"`
	UpdatedAt time.Time              `json:"updatedAt"`
	DeletedAt *time.Time             `json:"deletedAt,omitempty"`
}

const (
	AgentStatusOnline  AgentStatus = "online"
	AgentStatusOffline AgentStatus = "offline"

	TaskStatusPending   TaskStatus = "pending"
	TaskStatusLeased    TaskStatus = "leased"
	TaskStatusRunning   TaskStatus = "running"
	TaskStatusSucceeded TaskStatus = "succeeded"
	TaskStatusFailed    TaskStatus = "failed"
	TaskStatusCanceled  TaskStatus = "canceled"
)

type AgentHeartbeat struct {
	AgentID      uuid.UUID
	ObservedAt   time.Time
	Load         float64
	RunningTasks []string
}
