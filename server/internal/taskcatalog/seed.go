package taskcatalog

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Seed represents a built-in task catalog baseline (task types + profiles).
// It is intended for first-start bootstrap when the persisted catalog is empty.
type Seed struct {
	TaskTypes    []TaskType
	TaskProfiles []TaskProfile
}

// BuiltInSeed returns the task catalog baseline used for first-start bootstrap.
func BuiltInSeed() Seed {
	positive := func(v float64) *float64 { return &v }

	return Seed{
		TaskTypes: []TaskType{
			{Name: "respond", DisplayName: "Respond", Description: "Incident response automation modules", Capabilities: []string{"respond"}},
			{Name: "audit", DisplayName: "Audit", Description: "Host security auditing", Capabilities: []string{"audit"}},
			{Name: "inventory", DisplayName: "Inventory", Description: "Asset and port inventory scanning", Capabilities: []string{"inventory"}},
			{Name: "supplychain", DisplayName: "Supply Chain", Description: "SBOM generation and capture", Capabilities: []string{"supplychain"}},
			{Name: "baseline", DisplayName: "Baseline", Description: "Security baseline benchmark checks", Capabilities: []string{"baseline"}},
			{Name: "bas", DisplayName: "BAS", Description: "Breach and attack simulation", Capabilities: []string{"bas"}},
			{Name: "action", DisplayName: "Action", Description: "Automation task (placeholder)", Capabilities: []string{"action"}},
			{Name: "detect.diag", DisplayName: "Detect Diag", Description: "Detection diagnostics", Capabilities: []string{"detect.diag"}},
			{Name: "detect.memscan", DisplayName: "Detect Memscan", Description: "Memory scan (Windows-only)", Capabilities: []string{"detect.memscan"}},
		},
		TaskProfiles: []TaskProfile{
			{
				ID:          "default",
				TaskType:    "respond",
				DisplayName: "Respond Default",
				Version:     "1.0.0",
				Schema: TaskProfileSchema{
					Parameters: []ProfileParameter{
						{Key: "targets", Label: "Targets (comma-separated)", Type: "string", Required: true},
					},
				},
			},
			{
				ID:          "quick",
				TaskType:    "respond",
				DisplayName: "Respond Quick",
				Version:     "1.0.0",
				Schema: TaskProfileSchema{
					Parameters: []ProfileParameter{
						{Key: "targets", Label: "Targets (comma-separated)", Type: "string", Required: true},
					},
				},
			},
			{
				ID:          "audit",
				TaskType:    "audit",
				DisplayName: "Audit Default",
				Version:     "1.0.0",
				Schema: TaskProfileSchema{
					Parameters: []ProfileParameter{
						{Key: "scope", Label: "Scope", Type: "string", Default: "system"},
						{Key: "targets", Label: "Targets (comma-separated)", Type: "string"},
					},
				},
			},
			{
				ID:          "fast",
				TaskType:    "inventory",
				DisplayName: "Inventory Fast",
				Version:     "1.0.0",
				Schema: TaskProfileSchema{
					Parameters: []ProfileParameter{
						{Key: "targets", Label: "Targets (comma-separated)", Type: "string", Required: true},
						{Key: "ports", Label: "Ports", Type: "string"},
						{Key: "service-detect", Label: "Service Detect", Type: "boolean"},
						{Key: "os-detect", Label: "OS Detect", Type: "boolean"},
						{Key: "resolve", Label: "Resolve Hostnames", Type: "boolean"},
					},
				},
			},
			{
				ID:          "supplychain",
				TaskType:    "supplychain",
				DisplayName: "Supply Chain Default",
				Version:     "1.0.0",
				Schema: TaskProfileSchema{
					Parameters: []ProfileParameter{
						{Key: "mode", Label: "Mode", Type: "enum", Options: []string{"generate", "capture"}, Default: "generate"},
						{Key: "path", Label: "Path (comma-separated)", Type: "string"},
						{Key: "file", Label: "Input File", Type: "string"},
						{Key: "type", Label: "Output Type", Type: "enum", Options: []string{"json", "xml"}, Default: "json"},
					},
					Constraints: []ProfileConstraint{
						{Expression: `mode == "capture" OR path != "" OR file != ""`, Message: "supplychain.generate requires path or file"},
					},
				},
			},
			{
				ID:          "all",
				TaskType:    "baseline",
				DisplayName: "Baseline All",
				Version:     "1.0.0",
				Schema: TaskProfileSchema{
					Parameters: []ProfileParameter{
						{Key: "scope", Label: "Scope", Type: "string", Default: "all"},
						{Key: "baseline-config", Label: "Baseline Config Path", Type: "string"},
					},
				},
			},
			{
				ID:          "auto",
				TaskType:    "bas",
				DisplayName: "BAS Auto",
				Version:     "1.0.0",
				Schema: TaskProfileSchema{
					Parameters: []ProfileParameter{
						{Key: "scenario-id", Label: "Scenario ID", Type: "string"},
						{Key: "sandbox", Label: "Sandbox", Type: "boolean"},
						{Key: "no-sandbox", Label: "No Sandbox", Type: "boolean"},
						{Key: "sandbox-approve", Label: "Sandbox Approved", Type: "boolean"},
					},
				},
			},
			{
				ID:          "action",
				TaskType:    "action",
				DisplayName: "Action Default",
				Version:     "1.0.0",
				Schema: TaskProfileSchema{
					Parameters: []ProfileParameter{
						{Key: "command", Label: "Command", Type: "string"},
					},
				},
			},
			{
				ID:          "detect.diag",
				TaskType:    "detect.diag",
				DisplayName: "Detect Diag Default",
				Version:     "1.0.0",
				Schema: TaskProfileSchema{
					Parameters: []ProfileParameter{
						{Key: "backend", Label: "Backend", Type: "enum", Options: []string{"auto", "native", "portable"}, Default: "auto"},
						{Key: "rule", Label: "Rule Path", Type: "string", Default: ""},
					},
				},
			},
			{
				ID:          "detect.memscan",
				TaskType:    "detect.memscan",
				DisplayName: "Detect Memscan Default",
				Version:     "1.0.0",
				Schema: TaskProfileSchema{
					Parameters: []ProfileParameter{
						{Key: "pid", Label: "Process ID", Type: "number", Min: positive(1)},
						{Key: "all", Label: "Scan All Processes", Type: "boolean"},
						{Key: "backend", Label: "Backend", Type: "enum", Options: []string{"auto", "native", "portable"}, Default: "auto"},
						{Key: "rule", Label: "Rule Path", Type: "string", Default: ""},
						{Key: "rwx_only", Label: "RWX Only", Type: "boolean", Default: true},
						{Key: "max_bytes", Label: "Max Bytes", Type: "number", Min: positive(1), Default: 33554432},
						{Key: "max_regions", Label: "Max Regions", Type: "number", Min: positive(1), Default: 128},
						{Key: "evidence", Label: "Evidence", Type: "boolean", Default: false},
						{Key: "minidump", Label: "Minidump", Type: "boolean", Default: false},
					},
					Constraints: []ProfileConstraint{
						{Expression: "xor(pid, all)", Message: "exactly one of pid or all must be set"},
					},
				},
			},
		},
	}
}

// ImportSeedIfEmpty imports the provided seed definitions iff the current catalog is empty.
// Emptiness is defined as: taskTypes == 0 && taskProfiles == 0.
func (m *Manager) ImportSeedIfEmpty(ctx context.Context, seed Seed) (bool, error) {
	if m == nil {
		return false, errors.New("task catalog: nil manager")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if len(m.taskTypes) != 0 || len(m.taskProfiles) != 0 {
		return false, ctx.Err()
	}

	now := time.Now().UTC()
	for _, typ := range seed.TaskTypes {
		if err := validateTaskTypeInput(typ); err != nil {
			return false, err
		}
		key := strings.ToLower(strings.TrimSpace(typ.Name))
		if _, exists := m.taskTypes[key]; exists {
			return false, fmt.Errorf("task catalog seed: duplicate task type %s", typ.Name)
		}
		typ.CreatedAt = now
		typ.UpdatedAt = now
		m.taskTypes[key] = cloneTaskType(&typ)
	}

	for _, profile := range seed.TaskProfiles {
		if strings.TrimSpace(profile.ID) == "" {
			return false, errors.New("task catalog seed: profile id required")
		}
		normalizeTaskProfileNumericDefaults(&profile)
		if err := validateTaskProfileInput(profile); err != nil {
			return false, err
		}
		if _, ok := m.taskTypes[strings.ToLower(profile.TaskType)]; !ok {
			return false, fmt.Errorf("task catalog seed: profile %s references unknown task type %s", profile.ID, profile.TaskType)
		}
		if _, exists := m.taskProfiles[profile.ID]; exists {
			return false, fmt.Errorf("task catalog seed: duplicate profile id %s", profile.ID)
		}
		profile.CreatedAt = now
		profile.UpdatedAt = now
		m.taskProfiles[profile.ID] = cloneTaskProfile(&profile)
	}

	if err := m.persistLocked(); err != nil {
		return false, err
	}
	return true, ctx.Err()
}
