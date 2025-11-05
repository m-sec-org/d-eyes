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
	CreatedAt     time.Time         `json:"createdAt"`
	UpdatedAt     time.Time         `json:"updatedAt"`
}

type Task struct {
	ID         uuid.UUID         `json:"id"`
	Type       TaskType          `json:"type"`
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
	ID            uuid.UUID  `json:"id"`
	TaskID        uuid.UUID  `json:"taskId"`
	AgentID       uuid.UUID  `json:"agentId"`
	LeaseID       uuid.UUID  `json:"leaseId"`
	LeaseExpires  time.Time  `json:"leaseExpires"`
	StartedAt     *time.Time `json:"startedAt"`
	FinishedAt    *time.Time `json:"finishedAt"`
	Status        TaskStatus `json:"status"`
	ErrorMessage  string     `json:"errorMessage"`
	Summary       []byte     `json:"summary"`
	RetrySequence int        `json:"retrySequence"`
}

type Artifact struct {
	ID        uuid.UUID `json:"id"`
	TaskRunID uuid.UUID `json:"taskRunId"`
	Name      string    `json:"name"`
	MIMEType  string    `json:"mimeType"`
	Blob      []byte    `json:"blob"`
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
