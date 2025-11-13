package model

import (
	"time"

	"github.com/google/uuid"
)

type Playbook struct {
	ID          uuid.UUID          `json:"id"`
	Name        string             `json:"name"`
	Description string             `json:"description,omitempty"`
	Version     int                `json:"version"`
	Trigger     PlaybookTrigger    `json:"trigger"`
	Conditions  []string           `json:"conditions,omitempty"`
	Approvals   []PlaybookApproval `json:"approvals,omitempty"`
	Actions     []PlaybookAction   `json:"actions"`
	Rollback    []PlaybookAction   `json:"rollback,omitempty"`
	Status      string             `json:"status"`
	CreatedBy   string             `json:"created_by"`
	UpdatedBy   string             `json:"updated_by,omitempty"`
	ApprovedBy  string             `json:"approved_by,omitempty"`
	CreatedAt   time.Time          `json:"created_at"`
	UpdatedAt   time.Time          `json:"updated_at"`
	LastRunAt   *time.Time         `json:"last_run_at,omitempty"`
}

type PlaybookTrigger struct {
	Type   string            `json:"type"`
	Filter map[string]string `json:"filter,omitempty"`
}

type PlaybookApproval struct {
	Role    string        `json:"role"`
	Timeout time.Duration `json:"timeout,omitempty"`
}

type PlaybookAction struct {
	Type     string                 `json:"type"`
	Target   string                 `json:"target,omitempty"`
	TaskType string                 `json:"task_type,omitempty"`
	Payload  map[string]interface{} `json:"payload,omitempty"`
	Command  string                 `json:"command,omitempty"`
	Args     map[string]interface{} `json:"args,omitempty"`
	Metadata map[string]string      `json:"metadata,omitempty"`
}

type PlaybookRun struct {
	ID          uuid.UUID              `json:"id"`
	PlaybookID  uuid.UUID              `json:"playbook_id"`
	Status      string                 `json:"status"`
	TriggerType string                 `json:"trigger_type"`
	Event       map[string]interface{} `json:"event,omitempty"`
	Steps       []PlaybookRunStep      `json:"steps,omitempty"`
	Result      map[string]interface{} `json:"result,omitempty"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
	CompletedAt *time.Time             `json:"completed_at,omitempty"`
}

type PlaybookRunStep struct {
	Name        string                 `json:"name"`
	Type        string                 `json:"type"`
	Status      string                 `json:"status"`
	StartedAt   time.Time              `json:"started_at"`
	CompletedAt *time.Time             `json:"completed_at,omitempty"`
	Error       string                 `json:"error,omitempty"`
	Metadata    map[string]string      `json:"metadata,omitempty"`
	Result      map[string]interface{} `json:"result,omitempty"`
}
