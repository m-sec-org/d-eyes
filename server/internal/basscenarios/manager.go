package basscenarios

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"log/slog"
)

// Config drives persistence and defaults for BAS scenarios.
type Config struct {
	PersistPath           string
	DefaultResourceLimits ResourceLimits
	DefaultBoundaries     []string
}

// Manager manages BAS scenarios in-memory with optional persistence.
type Manager struct {
	mu       sync.RWMutex
	items    map[uuid.UUID]*Scenario
	cfg      Config
	log      *slog.Logger
	clockNow func() time.Time
}

// ScenarioStatus enumerates lifecycle states.
type ScenarioStatus string

const (
	StatusDraft    ScenarioStatus = "draft"
	StatusPending  ScenarioStatus = "pending"
	StatusApproved ScenarioStatus = "approved"
	StatusActive   ScenarioStatus = "active"
	StatusDisabled ScenarioStatus = "disabled"
)

// Scenario describes a BAS scenario blueprint.
type Scenario struct {
	ID                uuid.UUID      `json:"id"`
	Name              string         `json:"name"`
	Description       string         `json:"description,omitempty"`
	Tags              []string       `json:"tags,omitempty"`
	Status            ScenarioStatus `json:"status"`
	Steps             []ScenarioStep `json:"steps"`
	ResourceLimits    ResourceLimits `json:"resource_limits"`
	NetworkBoundaries []string       `json:"network_boundaries"`
	RequiresApproval  bool           `json:"requires_approval"`
	Approval          ApprovalState  `json:"approval"`
	CreatedBy         string         `json:"created_by,omitempty"`
	UpdatedBy         string         `json:"updated_by,omitempty"`
	CreatedAt         time.Time      `json:"created_at"`
	UpdatedAt         time.Time      `json:"updated_at"`
}

// ScenarioStep defines a single automation step.
type ScenarioStep struct {
	ID             string         `json:"id"`
	Name           string         `json:"name"`
	Action         string         `json:"action"`
	Order          int            `json:"order"`
	Args           map[string]any `json:"args,omitempty"`
	TimeoutSeconds int            `json:"timeout_seconds,omitempty"`
	RequireSandbox bool           `json:"require_sandbox"`
}

// ResourceLimits restricts BAS execution scope.
type ResourceLimits struct {
	MaxTargets        int `json:"max_targets"`
	MaxParallelSteps  int `json:"max_parallel_steps"`
	MaxDurationMinute int `json:"max_duration_minutes"`
	MaxCPUPercent     int `json:"max_cpu_percent"`
}

// ApprovalState records approval metadata.
type ApprovalState struct {
	ApprovedBy string     `json:"approved_by,omitempty"`
	ApprovedAt *time.Time `json:"approved_at,omitempty"`
	Notes      string     `json:"notes,omitempty"`
}

var (
	// ErrNotFound indicates scenario missing.
	ErrNotFound = errors.New("bas scenario: not found")
	// ErrInvalidStatusTransition indicates invalid lifecycle change.
	ErrInvalidStatusTransition = errors.New("bas scenario: invalid status transition")
)

type persistFile struct {
	Scenarios []Scenario `json:"scenarios"`
}

// NewManager creates a scenario manager.
func NewManager(cfg Config, log *slog.Logger) (*Manager, error) {
	if log == nil {
		log = slog.New(slog.NewTextHandler(os.Stdout, nil))
	}
	m := &Manager{
		items:    make(map[uuid.UUID]*Scenario),
		cfg:      cfg,
		log:      log,
		clockNow: func() time.Time { return time.Now().UTC() },
	}
	if cfg.PersistPath != "" {
		if err := m.load(); err != nil {
			return nil, err
		}
	}
	return m, nil
}

// List returns all scenarios.
func (m *Manager) List(ctx context.Context) ([]Scenario, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]Scenario, 0, len(m.items))
	for _, item := range m.items {
		result = append(result, *cloneScenario(item))
	}
	sort.Slice(result, func(i, j int) bool {
		return strings.ToLower(result[i].Name) < strings.ToLower(result[j].Name)
	})
	return result, ctx.Err()
}

// Get fetches a scenario by ID.
func (m *Manager) Get(ctx context.Context, id uuid.UUID) (*Scenario, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	item, ok := m.items[id]
	if !ok {
		return nil, ErrNotFound
	}
	return cloneScenario(item), ctx.Err()
}

// Create inserts a new scenario with defaults applied.
func (m *Manager) Create(ctx context.Context, input Scenario) (*Scenario, error) {
	if err := validateScenario(input); err != nil {
		return nil, err
	}
	now := m.clockNow()
	scenario := input
	scenario.ID = uuid.New()
	scenario.Status = StatusDraft
	applyDefaults(&scenario, m.cfg)
	scenario.CreatedAt = now
	scenario.UpdatedAt = now
	scenario.Steps = normalizeSteps(scenario.Steps)

	m.mu.Lock()
	defer m.mu.Unlock()
	m.items[scenario.ID] = cloneScenario(&scenario)
	if err := m.persistLocked(); err != nil {
		return nil, err
	}
	return cloneScenario(&scenario), ctx.Err()
}

// Update replaces an existing scenario (allowed when not active).
func (m *Manager) Update(ctx context.Context, id uuid.UUID, input Scenario) (*Scenario, error) {
	if err := validateScenario(input); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	current, ok := m.items[id]
	if !ok {
		return nil, ErrNotFound
	}
	if current.Status == StatusActive {
		return nil, fmt.Errorf("bas scenario: active scenario不可直接修改")
	}
	applyDefaults(&input, m.cfg)
	now := m.clockNow()
	input.ID = id
	input.Status = current.Status
	input.Approval = current.Approval
	input.CreatedAt = current.CreatedAt
	input.UpdatedAt = now
	input.Steps = normalizeSteps(input.Steps)
	m.items[id] = cloneScenario(&input)
	if err := m.persistLocked(); err != nil {
		return nil, err
	}
	return cloneScenario(m.items[id]), ctx.Err()
}

// Approve marks a scenario as approved.
func (m *Manager) Approve(ctx context.Context, id uuid.UUID, approver, notes string) (*Scenario, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	item, ok := m.items[id]
	if !ok {
		return nil, ErrNotFound
	}
	if item.Status == StatusDisabled {
		return nil, ErrInvalidStatusTransition
	}
	now := m.clockNow()
	item.Status = StatusApproved
	item.Approval = ApprovalState{
		ApprovedBy: approver,
		ApprovedAt: &now,
		Notes:      notes,
	}
	item.UpdatedAt = now
	if err := m.persistLocked(); err != nil {
		return nil, err
	}
	return cloneScenario(item), ctx.Err()
}

// SetStatus transitions scenario status (activate/deactivate/pending).
func (m *Manager) SetStatus(ctx context.Context, id uuid.UUID, status ScenarioStatus) (*Scenario, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	item, ok := m.items[id]
	if !ok {
		return nil, ErrNotFound
	}
	if err := validateStatusTransition(item.Status, status); err != nil {
		return nil, err
	}
	item.Status = status
	item.UpdatedAt = m.clockNow()
	if err := m.persistLocked(); err != nil {
		return nil, err
	}
	return cloneScenario(item), ctx.Err()
}

// Delete removes a scenario.
func (m *Manager) Delete(ctx context.Context, id uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.items[id]; !ok {
		return ErrNotFound
	}
	delete(m.items, id)
	return m.persistLocked()
}

// ValidateScenarioUsed ensures scenario can run (status + approval) used by task creation.
func (m *Manager) ValidateScenarioExecutable(id uuid.UUID) (*Scenario, error) {
	return m.Get(context.Background(), id) // caller will re-check status
}

func validateScenario(input Scenario) error {
	if strings.TrimSpace(input.Name) == "" {
		return errors.New("bas scenario: name required")
	}
	if len(input.Steps) == 0 {
		return errors.New("bas scenario: at least one step required")
	}
	for _, step := range input.Steps {
		if strings.TrimSpace(step.Name) == "" {
			return fmt.Errorf("bas scenario: step name required")
		}
		if strings.TrimSpace(step.Action) == "" {
			return fmt.Errorf("bas scenario: step action required")
		}
	}
	return nil
}

func applyDefaults(scenario *Scenario, cfg Config) {
	if len(scenario.NetworkBoundaries) == 0 && len(cfg.DefaultBoundaries) > 0 {
		scenario.NetworkBoundaries = append([]string(nil), cfg.DefaultBoundaries...)
	}
	scenario.ResourceLimits = mergeLimits(cfg.DefaultResourceLimits, scenario.ResourceLimits)
}

func mergeLimits(base, override ResourceLimits) ResourceLimits {
	result := base
	if override.MaxTargets > 0 {
		result.MaxTargets = override.MaxTargets
	}
	if override.MaxParallelSteps > 0 {
		result.MaxParallelSteps = override.MaxParallelSteps
	}
	if override.MaxDurationMinute > 0 {
		result.MaxDurationMinute = override.MaxDurationMinute
	}
	if override.MaxCPUPercent > 0 {
		result.MaxCPUPercent = override.MaxCPUPercent
	}
	return result
}

func normalizeSteps(steps []ScenarioStep) []ScenarioStep {
	result := make([]ScenarioStep, len(steps))
	for idx, step := range steps {
		if strings.TrimSpace(step.ID) == "" {
			step.ID = uuid.NewString()
		}
		step.Order = idx + 1
		result[idx] = step
	}
	return result
}

func validateStatusTransition(current, next ScenarioStatus) error {
	if current == next {
		return nil
	}
	switch next {
	case StatusActive:
		if current != StatusApproved {
			return ErrInvalidStatusTransition
		}
	case StatusApproved:
		if current != StatusPending && current != StatusDraft {
			return ErrInvalidStatusTransition
		}
	case StatusPending:
		if current != StatusDraft {
			return ErrInvalidStatusTransition
		}
	case StatusDisabled:
		// always allow disable
	default:
		return ErrInvalidStatusTransition
	}
	return nil
}

func (m *Manager) persistLocked() error {
	if m.cfg.PersistPath == "" {
		return nil
	}
	payload := persistFile{
		Scenarios: make([]Scenario, 0, len(m.items)),
	}
	for _, item := range m.items {
		payload.Scenarios = append(payload.Scenarios, *cloneScenario(item))
	}
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(m.cfg.PersistPath), 0o755); err != nil {
		return err
	}
	tmp := m.cfg.PersistPath + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, m.cfg.PersistPath)
}

func (m *Manager) load() error {
	data, err := os.ReadFile(m.cfg.PersistPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	var payload persistFile
	if err := json.Unmarshal(data, &payload); err != nil {
		return err
	}
	for i := range payload.Scenarios {
		scenario := payload.Scenarios[i]
		if scenario.ID == uuid.Nil {
			scenario.ID = uuid.New()
		}
		applyDefaults(&scenario, m.cfg)
		m.items[scenario.ID] = cloneScenario(&scenario)
	}
	return nil
}

func cloneScenario(in *Scenario) *Scenario {
	if in == nil {
		return nil
	}
	cp := *in
	if in.Tags != nil {
		cp.Tags = append([]string(nil), in.Tags...)
	}
	if in.NetworkBoundaries != nil {
		cp.NetworkBoundaries = append([]string(nil), in.NetworkBoundaries...)
	}
	if in.Steps != nil {
		cp.Steps = make([]ScenarioStep, len(in.Steps))
		copy(cp.Steps, in.Steps)
		for idx := range cp.Steps {
			if in.Steps[idx].Args != nil {
				cp.Steps[idx].Args = copyMap(in.Steps[idx].Args)
			}
		}
	}
	return &cp
}

func copyMap(src map[string]any) map[string]any {
	dst := make(map[string]any, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}
