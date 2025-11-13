package model

import (
	"time"

	"github.com/google/uuid"
)

type ComplianceFramework struct {
	ID          uuid.UUID `json:"id"`
	Key         string    `json:"key"`
	Title       string    `json:"title"`
	Version     string    `json:"version"`
	Description string    `json:"description,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type ComplianceControl struct {
	ID          uuid.UUID         `json:"id"`
	FrameworkID uuid.UUID         `json:"framework_id"`
	Code        string            `json:"code"`
	Title       string            `json:"title"`
	Severity    string            `json:"severity"`
	Description string            `json:"description,omitempty"`
	References  map[string]string `json:"references,omitempty"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
}

type ControlMapping struct {
	ID         uuid.UUID         `json:"id"`
	ControlID  uuid.UUID         `json:"control_id"`
	TargetType string            `json:"target_type"`
	TargetRef  string            `json:"target_ref"`
	Metadata   map[string]string `json:"metadata,omitempty"`
	CreatedAt  time.Time         `json:"created_at"`
}

type ComplianceFinding struct {
	ID              uuid.UUID         `json:"id"`
	FrameworkID     uuid.UUID         `json:"framework_id"`
	ControlID       uuid.UUID         `json:"control_id"`
	AssetRef        string            `json:"asset_ref"`
	Status          string            `json:"status"`
	Evidence        map[string]string `json:"evidence,omitempty"`
	RemediationLogs []RemediationNote `json:"remediation_logs,omitempty"`
	CreatedAt       time.Time         `json:"created_at"`
	UpdatedAt       time.Time         `json:"updated_at"`
}

type RemediationNote struct {
	Author    string    `json:"author"`
	Note      string    `json:"note"`
	Timestamp time.Time `json:"timestamp"`
}
