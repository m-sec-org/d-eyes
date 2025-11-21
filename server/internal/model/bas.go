package model

import (
	"time"

	"github.com/google/uuid"
)

// BASScenario captures the persisted definition of a BAS (breach and attack simulation) scenario.
type BASScenario struct {
	ID                uuid.UUID                   `json:"id"`
	Name              string                      `json:"name"`
	Version           int                         `json:"version"`
	Description       string                      `json:"description,omitempty"`
	Tags              []string                    `json:"tags,omitempty"`
	Status            string                      `json:"status"`
	Steps             []BASScenarioStep           `json:"steps"`
	ResourceLimits    BASResourceLimits           `json:"resource_limits"`
	NetworkBoundaries []string                    `json:"network_boundaries,omitempty"`
	RequiresApproval  bool                        `json:"requires_approval"`
	Approval          BASScenarioApprovalState    `json:"approval"`
	ApprovalRecords   []BASScenarioApprovalRecord `json:"approval_records,omitempty"`
	ApprovalPolicy    []BASApprovalRule           `json:"approval_policy,omitempty"`
	Dependencies      []uuid.UUID                 `json:"dependencies,omitempty"`
	RequiredLabels    []string                    `json:"required_labels,omitempty"`
	ExecutionPlan     BASExecutionPlan            `json:"execution_plan"`
	CreatedBy         string                      `json:"created_by,omitempty"`
	UpdatedBy         string                      `json:"updated_by,omitempty"`
	CreatedAt         time.Time                   `json:"created_at"`
	UpdatedAt         time.Time                   `json:"updated_at"`
	PublishedAt       *time.Time                  `json:"published_at,omitempty"`
}

// BASScenarioStep describes a single step within a BAS scenario.
type BASScenarioStep struct {
	ID               string                 `json:"id"`
	Name             string                 `json:"name"`
	Action           string                 `json:"action"`
	Order            int                    `json:"order"`
	Args             map[string]any         `json:"args,omitempty"`
	TimeoutSeconds   int                    `json:"timeout_seconds,omitempty"`
	RequireSandbox   bool                   `json:"require_sandbox"`
	AgentProfile     string                 `json:"agent_profile,omitempty"`
	Capabilities     []string               `json:"capabilities,omitempty"`
	DependsOn        []string               `json:"depends_on,omitempty"`
	ParallelGroup    string                 `json:"parallel_group,omitempty"`
	Severity         string                 `json:"severity,omitempty"`
	ExpectArtifacts  bool                   `json:"expect_artifacts,omitempty"`
	TelemetryHints   map[string]string      `json:"telemetry_hints,omitempty"`
	ExecutionContext map[string]interface{} `json:"execution_context,omitempty"`
}

// BASResourceLimits restricts how aggressive a scenario may be executed.
type BASResourceLimits struct {
	MaxTargets        int `json:"max_targets"`
	MaxParallelSteps  int `json:"max_parallel_steps"`
	MaxDurationMinute int `json:"max_duration_minutes"`
	MaxCPUPercent     int `json:"max_cpu_percent"`
}

// BASScenarioApprovalState tracks approval metadata for scenarios that require it.
type BASScenarioApprovalState struct {
	ApprovedBy string     `json:"approved_by,omitempty"`
	ApprovedAt *time.Time `json:"approved_at,omitempty"`
	Notes      string     `json:"notes,omitempty"`
}

type BASScenarioApprovalRecord struct {
	Role      string     `json:"role"`
	Status    string     `json:"status"`
	Actor     string     `json:"actor,omitempty"`
	Notes     string     `json:"notes,omitempty"`
	UpdatedAt *time.Time `json:"updated_at,omitempty"`
}

const (
	ScenarioApprovalPending  = "pending"
	ScenarioApprovalApproved = "approved"
	ScenarioApprovalRejected = "rejected"
)

// BASApprovalRule defines a single approver requirement (mirrors playbook approval rules).
type BASApprovalRule struct {
	Role           string `json:"role"`
	TimeoutSeconds int    `json:"timeout_seconds,omitempty"`
}

// BASExecutionPlan models how BAS steps should be orchestrated.
type BASExecutionPlan struct {
	Mode               string `json:"mode"` // serial | parallel
	MaxParallel        int    `json:"max_parallel,omitempty"`
	RetryLimit         int    `json:"retry_limit,omitempty"`
	StepTimeoutSeconds int    `json:"step_timeout_seconds,omitempty"`
	CrossAgent         bool   `json:"cross_agent,omitempty"`
}
