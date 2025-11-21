package basscenarios

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"log/slog"

	"github.com/m-sec-org/d-eyes/server/internal/model"
	"github.com/m-sec-org/d-eyes/server/internal/store"
)

// Shared model aliases to avoid duplicating struct definitions.
type (
	Scenario       = model.BASScenario
	ScenarioStep   = model.BASScenarioStep
	ResourceLimits = model.BASResourceLimits
	ApprovalState  = model.BASScenarioApprovalState
	ApprovalRecord = model.BASScenarioApprovalRecord
	ApprovalRule   = model.BASApprovalRule
	ExecutionPlan  = model.BASExecutionPlan
)

const (
	scenarioApprovalPending  = model.ScenarioApprovalPending
	scenarioApprovalApproved = model.ScenarioApprovalApproved
	scenarioApprovalRejected = model.ScenarioApprovalRejected

	// Re-export approval states for callers that depend on package constants.
	ScenarioApprovalPending  = scenarioApprovalPending
	ScenarioApprovalApproved = scenarioApprovalApproved
	ScenarioApprovalRejected = scenarioApprovalRejected
)

// Config drives persistence and defaults for BAS scenarios.
type Config struct {
	Store                 store.Store
	DefaultResourceLimits ResourceLimits
	DefaultBoundaries     []string
	DefaultExecutionPlan  ExecutionPlan
	DefaultApprovalPolicy []ApprovalRule
	CacheTTL              time.Duration
}

// Manager manages BAS scenarios backed by the configured store.
type Manager struct {
	store    store.Store
	cfg      Config
	log      *slog.Logger
	clockNow func() time.Time
	cacheMu  sync.RWMutex
	cache    map[uuid.UUID]*Scenario
	cacheTTL time.Duration
	cacheExp time.Time
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

var (
	// ErrNotFound indicates scenario missing.
	ErrNotFound = errors.New("bas scenario: not found")
	// ErrInvalidStatusTransition indicates invalid lifecycle change.
	ErrInvalidStatusTransition = errors.New("bas scenario: invalid status transition")
	// ErrStoreUnavailable indicates persistence layer missing.
	ErrStoreUnavailable = errors.New("bas scenario: store unavailable")
)

// NewManager creates a scenario manager backed by the provided store.
func NewManager(cfg Config, log *slog.Logger) (*Manager, error) {
	if cfg.Store == nil {
		return nil, ErrStoreUnavailable
	}
	if log == nil {
		log = slog.Default()
	}
	cfg.DefaultExecutionPlan = normalizeExecutionPlan(cfg.DefaultExecutionPlan, ExecutionPlan{})
	cacheTTL := cfg.CacheTTL
	if cacheTTL < 0 {
		cacheTTL = 0
	}
	var cache map[uuid.UUID]*Scenario
	if cacheTTL > 0 {
		cache = make(map[uuid.UUID]*Scenario)
	}
	m := &Manager{
		store: cfg.Store,
		cfg:   cfg,
		log:   log,
		clockNow: func() time.Time {
			return time.Now().UTC()
		},
		cacheTTL: cacheTTL,
		cache:    cache,
	}
	return m, nil
}

// List returns all scenarios sorted by name.
func (m *Manager) List(ctx context.Context) ([]Scenario, error) {
	if m.cacheEnabled() {
		if err := m.ensureCache(ctx); err == nil {
			result := m.snapshotCache()
			sort.Slice(result, func(i, j int) bool {
				return strings.ToLower(result[i].Name) < strings.ToLower(result[j].Name)
			})
			return result, nil
		}
	}
	records, err := m.store.ListBASScenarios(ctx)
	if err != nil {
		return nil, translateStoreError(err)
	}
	result := make([]Scenario, 0, len(records))
	for _, rec := range records {
		result = append(result, *cloneScenario(rec))
	}
	sort.Slice(result, func(i, j int) bool {
		return strings.ToLower(result[i].Name) < strings.ToLower(result[j].Name)
	})
	if m.cacheEnabled() {
		m.backfillCache(result)
	}
	return result, nil
}

// Get fetches a scenario by ID.
func (m *Manager) Get(ctx context.Context, id uuid.UUID) (*Scenario, error) {
	if m.cacheEnabled() {
		if err := m.ensureCache(ctx); err == nil {
			if scenario := m.getCachedScenario(id); scenario != nil {
				return scenario, nil
			}
		}
	}
	record, err := m.store.GetBASScenario(ctx, id)
	if err != nil {
		return nil, translateStoreError(err)
	}
	m.cacheScenario(record)
	return cloneScenario(record), nil
}

// Create inserts a new scenario with defaults applied.
func (m *Manager) Create(ctx context.Context, input Scenario) (*Scenario, error) {
	scenario := cloneScenario(&input)
	now := m.clockNow()
	scenario.ID = uuid.New()
	scenario.Status = StatusDraft.String()
	scenario.Version = 1
	scenario.CreatedAt = now
	scenario.UpdatedAt = now
	scenario.PublishedAt = nil
	scenario.Approval = ApprovalState{}
	scenario.Steps = normalizeSteps(scenario.Steps)
	m.applyDefaults(scenario)
	m.ensureApprovalRecords(scenario)
	if err := validateScenario(scenario); err != nil {
		return nil, err
	}
	if err := m.store.CreateBASScenario(ctx, scenario); err != nil {
		return nil, fmt.Errorf("bas scenario: create: %w", err)
	}
	m.cacheScenario(scenario)
	return cloneScenario(scenario), nil
}

// Update replaces an existing scenario (allowed when not active).
func (m *Manager) Update(ctx context.Context, id uuid.UUID, input Scenario) (*Scenario, error) {
	current, err := m.store.GetBASScenario(ctx, id)
	if err != nil {
		return nil, translateStoreError(err)
	}
	if ScenarioStatus(current.Status) == StatusActive {
		return nil, fmt.Errorf("bas scenario: active scenario不可直接修改")
	}
	scenario := cloneScenario(&input)
	scenario.ID = id
	scenario.Version = current.Version
	scenario.Status = current.Status
	scenario.CreatedAt = current.CreatedAt
	scenario.UpdatedAt = m.clockNow()
	scenario.Approval = current.Approval
	scenario.ApprovalRecords = current.ApprovalRecords
	scenario.PublishedAt = current.PublishedAt
	if scenario.CreatedBy == "" {
		scenario.CreatedBy = current.CreatedBy
	}
	scenario.Steps = normalizeSteps(scenario.Steps)
	m.applyDefaults(scenario)
	m.ensureApprovalRecords(scenario)
	if err := validateScenario(scenario); err != nil {
		return nil, err
	}
	if err := m.store.UpdateBASScenario(ctx, scenario); err != nil {
		return nil, fmt.Errorf("bas scenario: update: %w", err)
	}
	m.cacheScenario(scenario)
	return cloneScenario(scenario), nil
}

// Publish bumps version and moves a draft scenario into pending approval.
func (m *Manager) Publish(ctx context.Context, id uuid.UUID, updatedBy string) (*Scenario, error) {
	scenario, err := m.store.GetBASScenario(ctx, id)
	if err != nil {
		return nil, translateStoreError(err)
	}
	switch ScenarioStatus(scenario.Status) {
	case StatusDraft, StatusDisabled:
	default:
		return nil, fmt.Errorf("bas scenario: only draft/disabled scenarios can be published")
	}
	now := m.clockNow()
	scenario.Status = StatusPending.String()
	scenario.Version++
	scenario.Approval = ApprovalState{}
	resetApprovalRecords(scenario.ApprovalRecords)
	scenario.PublishedAt = &now
	scenario.UpdatedAt = now
	scenario.UpdatedBy = updatedBy
	if err := m.store.UpdateBASScenario(ctx, scenario); err != nil {
		return nil, fmt.Errorf("bas scenario: publish: %w", err)
	}
	m.cacheScenario(scenario)
	return cloneScenario(scenario), nil
}

// Approve marks a scenario as approved.
func (m *Manager) Approve(ctx context.Context, id uuid.UUID, approver, notes string) (*Scenario, error) {
	return m.UpdateApproval(ctx, id, "", approver, "approve", notes)
}

// SetStatus transitions scenario status (activate/deactivate/pending).
func (m *Manager) SetStatus(ctx context.Context, id uuid.UUID, status ScenarioStatus) (*Scenario, error) {
	scenario, err := m.store.GetBASScenario(ctx, id)
	if err != nil {
		return nil, translateStoreError(err)
	}
	if err := validateStatusTransition(ScenarioStatus(scenario.Status), status); err != nil {
		return nil, err
	}
	scenario.Status = status.String()
	scenario.UpdatedAt = m.clockNow()
	if status == StatusDraft {
		scenario.Approval = ApprovalState{}
		resetApprovalRecords(scenario.ApprovalRecords)
	}
	if err := m.store.UpdateBASScenario(ctx, scenario); err != nil {
		return nil, fmt.Errorf("bas scenario: set status: %w", err)
	}
	m.cacheScenario(scenario)
	return cloneScenario(scenario), nil
}

// Delete removes a scenario.
func (m *Manager) Delete(ctx context.Context, id uuid.UUID) error {
	if err := m.store.DeleteBASScenario(ctx, id); err != nil {
		return translateStoreError(err)
	}
	m.removeCachedScenario(id)
	return nil
}

// Clone duplicates an existing scenario into a new draft.
func (m *Manager) Clone(ctx context.Context, id uuid.UUID, createdBy, name string) (*Scenario, error) {
	source, err := m.store.GetBASScenario(ctx, id)
	if err != nil {
		return nil, translateStoreError(err)
	}
	clone := cloneScenario(source)
	clone.ID = uuid.New()
	clone.Status = StatusDraft.String()
	clone.Version = 1
	clone.CreatedAt = m.clockNow()
	clone.UpdatedAt = clone.CreatedAt
	if strings.TrimSpace(createdBy) != "" {
		clone.CreatedBy = createdBy
		clone.UpdatedBy = createdBy
	} else {
		clone.CreatedBy = source.CreatedBy
		clone.UpdatedBy = source.UpdatedBy
	}
	clone.Approval = ApprovalState{}
	resetApprovalRecords(clone.ApprovalRecords)
	clone.PublishedAt = nil
	if strings.TrimSpace(name) != "" {
		clone.Name = name
	} else {
		clone.Name = fmt.Sprintf("%s (copy)", clone.Name)
	}
	if err := m.store.CreateBASScenario(ctx, clone); err != nil {
		return nil, fmt.Errorf("bas scenario: clone: %w", err)
	}
	m.cacheScenario(clone)
	return cloneScenario(clone), nil
}

// ValidateScenarioExecutable ensures scenario can run (status + approval) used by task creation.
func (m *Manager) ValidateScenarioExecutable(ctx context.Context, id uuid.UUID) (*Scenario, error) {
	return m.Get(ctx, id)
}

// UpdateApproval handles role-based approvals/rejections.
func (m *Manager) UpdateApproval(ctx context.Context, id uuid.UUID, role, actor, action, notes string) (*Scenario, error) {
	scenario, err := m.store.GetBASScenario(ctx, id)
	if err != nil {
		return nil, translateStoreError(err)
	}
	if ScenarioStatus(scenario.Status) == StatusDisabled {
		return nil, ErrInvalidStatusTransition
	}
	m.ensureApprovalRecords(scenario)
	if len(scenario.ApprovalRecords) == 0 {
		return nil, fmt.Errorf("bas scenario: no approval policy configured")
	}
	idx := selectApprovalIndex(scenario.ApprovalRecords, role)
	if idx < 0 {
		return nil, fmt.Errorf("bas scenario: pending approval not found")
	}
	for i := 0; i < idx; i++ {
		if scenario.ApprovalRecords[i].Status != scenarioApprovalApproved {
			return nil, fmt.Errorf("bas scenario: previous approval %q pending", scenario.ApprovalRecords[i].Role)
		}
	}
	now := m.clockNow()
	state := &scenario.ApprovalRecords[idx]
	switch strings.ToLower(strings.TrimSpace(action)) {
	case "approve", "approved", "":
		state.Status = scenarioApprovalApproved
	case "reject", "rejected":
		state.Status = scenarioApprovalRejected
	default:
		return nil, fmt.Errorf("bas scenario: invalid approval action %q", action)
	}
	state.Actor = actor
	state.Notes = notes
	state.UpdatedAt = &now
	scenario.Approval = snapshotApprovalState(scenario.ApprovalRecords)
	scenario.UpdatedAt = now
	scenario.UpdatedBy = actor
	if state.Status == scenarioApprovalRejected {
		scenario.Status = StatusPending.String()
		resetFollowingRecords(scenario.ApprovalRecords, idx+1)
	} else if allScenarioApprovalsApproved(scenario.ApprovalRecords) {
		scenario.Status = StatusApproved.String()
	}
	if err := m.store.UpdateBASScenario(ctx, scenario); err != nil {
		return nil, fmt.Errorf("bas scenario: update approval: %w", err)
	}
	m.cacheScenario(scenario)
	return cloneScenario(scenario), nil
}

func (m *Manager) applyDefaults(scenario *Scenario) {
	if scenario == nil {
		return
	}
	if len(scenario.NetworkBoundaries) == 0 && len(m.cfg.DefaultBoundaries) > 0 {
		scenario.NetworkBoundaries = append([]string(nil), m.cfg.DefaultBoundaries...)
	}
	scenario.ResourceLimits = mergeLimits(m.cfg.DefaultResourceLimits, scenario.ResourceLimits)
	scenario.ExecutionPlan = normalizeExecutionPlan(scenario.ExecutionPlan, m.cfg.DefaultExecutionPlan)
	if len(scenario.ApprovalPolicy) == 0 && len(m.cfg.DefaultApprovalPolicy) > 0 {
		scenario.ApprovalPolicy = append([]ApprovalRule(nil), m.cfg.DefaultApprovalPolicy...)
	}
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

func normalizeExecutionPlan(plan, defaults ExecutionPlan) ExecutionPlan {
	result := defaults
	mode := strings.ToLower(strings.TrimSpace(plan.Mode))
	if mode == "" && defaults.Mode == "" {
		mode = "serial"
	}
	if mode != "" {
		result.Mode = mode
	}
	if plan.MaxParallel > 0 {
		result.MaxParallel = plan.MaxParallel
	} else if result.MaxParallel <= 0 {
		result.MaxParallel = 1
	}
	if plan.RetryLimit > 0 {
		result.RetryLimit = plan.RetryLimit
	}
	if plan.StepTimeoutSeconds > 0 {
		result.StepTimeoutSeconds = plan.StepTimeoutSeconds
	}
	if plan.CrossAgent {
		result.CrossAgent = true
	}
	return result
}

func normalizeSteps(steps []ScenarioStep) []ScenarioStep {
	result := make([]ScenarioStep, len(steps))
	seen := make(map[string]int)
	for idx, step := range steps {
		step.ID = strings.TrimSpace(step.ID)
		if step.ID == "" {
			step.ID = uuid.NewString()
		}
		if n := seen[step.ID]; n > 0 {
			step.ID = fmt.Sprintf("%s-%d", step.ID, n+1)
		}
		seen[step.ID]++
		step.Order = idx + 1
		if step.Args != nil {
			step.Args = copyMap(step.Args)
		}
		if len(step.DependsOn) > 0 {
			for i, dep := range step.DependsOn {
				step.DependsOn[i] = strings.TrimSpace(dep)
			}
		}
		result[idx] = step
	}
	return result
}

func (m *Manager) ensureApprovalRecords(scenario *Scenario) {
	if scenario == nil {
		return
	}
	if len(scenario.ApprovalPolicy) == 0 {
		scenario.ApprovalRecords = nil
		scenario.Approval = ApprovalState{}
		return
	}
	existing := make(map[string]ApprovalRecord)
	for _, rec := range scenario.ApprovalRecords {
		key := strings.ToLower(strings.TrimSpace(rec.Role))
		if key == "" {
			continue
		}
		existing[key] = rec
	}
	records := make([]ApprovalRecord, len(scenario.ApprovalPolicy))
	for i, rule := range scenario.ApprovalPolicy {
		key := strings.ToLower(strings.TrimSpace(rule.Role))
		rec, ok := existing[key]
		if !ok {
			rec = model.BASScenarioApprovalRecord{Role: rule.Role, Status: scenarioApprovalPending}
		}
		records[i] = rec
	}
	scenario.ApprovalRecords = records
	scenario.Approval = snapshotApprovalState(records)
}

func snapshotApprovalState(records []ApprovalRecord) ApprovalState {
	for i := len(records) - 1; i >= 0; i-- {
		if records[i].Status == scenarioApprovalApproved && records[i].Actor != "" {
			return ApprovalState{ApprovedBy: records[i].Actor, ApprovedAt: records[i].UpdatedAt, Notes: records[i].Notes}
		}
	}
	return ApprovalState{}
}

func allScenarioApprovalsApproved(records []ApprovalRecord) bool {
	if len(records) == 0 {
		return true
	}
	for _, rec := range records {
		if rec.Status != scenarioApprovalApproved {
			return false
		}
	}
	return true
}

// IsScenarioApproved reports whether a scenario has passed all approvals.
func IsScenarioApproved(scenario *Scenario) bool {
	if scenario == nil {
		return false
	}
	return allScenarioApprovalsApproved(scenario.ApprovalRecords) || ScenarioStatus(scenario.Status) == StatusApproved || ScenarioStatus(scenario.Status) == StatusActive
}

func selectApprovalIndex(records []ApprovalRecord, role string) int {
	if len(records) == 0 {
		return -1
	}
	if strings.TrimSpace(role) == "" {
		for i, rec := range records {
			if rec.Status == scenarioApprovalPending {
				return i
			}
		}
		return -1
	}
	key := strings.ToLower(strings.TrimSpace(role))
	for i, rec := range records {
		if strings.ToLower(strings.TrimSpace(rec.Role)) == key {
			return i
		}
	}
	return -1
}

func resetApprovalRecords(records []ApprovalRecord) {
	resetFollowingRecords(records, 0)
}

func resetFollowingRecords(records []ApprovalRecord, start int) {
	for i := start; i < len(records); i++ {
		records[i].Status = scenarioApprovalPending
		records[i].Actor = ""
		records[i].Notes = ""
		records[i].UpdatedAt = nil
	}
}

func copyMap(src map[string]any) map[string]any {
	if len(src) == 0 {
		return nil
	}
	dst := make(map[string]any, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

func validateScenario(scenario *Scenario) error {
	if scenario == nil {
		return errors.New("bas scenario: nil scenario")
	}
	if strings.TrimSpace(scenario.Name) == "" {
		return errors.New("bas scenario: name required")
	}
	if len(scenario.Steps) == 0 {
		return errors.New("bas scenario: at least one step required")
	}
	stepIDs := make(map[string]struct{})
	for _, step := range scenario.Steps {
		if strings.TrimSpace(step.Name) == "" {
			return fmt.Errorf("bas scenario: step name required")
		}
		if strings.TrimSpace(step.Action) == "" {
			return fmt.Errorf("bas scenario: step action required")
		}
		if strings.TrimSpace(step.ID) == "" {
			return errors.New("bas scenario: step id missing")
		}
		stepIDs[step.ID] = struct{}{}
	}
	for _, step := range scenario.Steps {
		for _, dep := range step.DependsOn {
			dep = strings.TrimSpace(dep)
			if dep == "" {
				continue
			}
			if _, ok := stepIDs[dep]; !ok {
				return fmt.Errorf("bas scenario: step %s depends on unknown step %s", step.Name, dep)
			}
			if dep == step.ID {
				return fmt.Errorf("bas scenario: step %s cannot depend on itself", step.Name)
			}
		}
	}
	mode := strings.ToLower(strings.TrimSpace(scenario.ExecutionPlan.Mode))
	if mode != "serial" && mode != "parallel" {
		return fmt.Errorf("bas scenario: execution_plan.mode must be serial or parallel")
	}
	if mode == "parallel" && scenario.ExecutionPlan.MaxParallel <= 0 {
		return fmt.Errorf("bas scenario: execution_plan.max_parallel must be > 0 for parallel mode")
	}
	if scenario.ExecutionPlan.RetryLimit < 0 {
		return fmt.Errorf("bas scenario: execution_plan.retry_limit must be >= 0")
	}
	if scenario.ExecutionPlan.StepTimeoutSeconds < 0 {
		return fmt.Errorf("bas scenario: execution_plan.step_timeout_seconds must be >= 0")
	}
	if scenario.ResourceLimits.MaxTargets < 0 || scenario.ResourceLimits.MaxParallelSteps < 0 ||
		scenario.ResourceLimits.MaxDurationMinute < 0 || scenario.ResourceLimits.MaxCPUPercent < 0 {
		return fmt.Errorf("bas scenario: resource limits must be non-negative")
	}
	return nil
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
		if current != StatusPending {
			return ErrInvalidStatusTransition
		}
	case StatusPending:
		if current != StatusDraft && current != StatusDisabled {
			return ErrInvalidStatusTransition
		}
	case StatusDisabled, StatusDraft:
		// always allow
	default:
		return ErrInvalidStatusTransition
	}
	return nil
}

func translateStoreError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, store.ErrNotFound) {
		return ErrNotFound
	}
	return err
}

func (s ScenarioStatus) String() string {
	return string(s)
}

func (m *Manager) cacheEnabled() bool {
	return m.cacheTTL > 0 && m.cache != nil
}

func (m *Manager) ensureCache(ctx context.Context) error {
	if !m.cacheEnabled() {
		return errors.New("cache disabled")
	}
	m.cacheMu.RLock()
	if len(m.cache) > 0 && time.Now().Before(m.cacheExp) {
		m.cacheMu.RUnlock()
		return nil
	}
	m.cacheMu.RUnlock()

	records, err := m.store.ListBASScenarios(ctx)
	if err != nil {
		return err
	}

	m.cacheMu.Lock()
	if m.cache == nil {
		m.cache = make(map[uuid.UUID]*Scenario, len(records))
	} else {
		for k := range m.cache {
			delete(m.cache, k)
		}
	}
	for _, rec := range records {
		if rec == nil {
			continue
		}
		m.cache[rec.ID] = cloneScenario(rec)
	}
	m.cacheExp = time.Now().Add(m.cacheTTL)
	m.cacheMu.Unlock()
	return nil
}

func (m *Manager) snapshotCache() []Scenario {
	m.cacheMu.RLock()
	defer m.cacheMu.RUnlock()
	result := make([]Scenario, 0, len(m.cache))
	for _, scenario := range m.cache {
		result = append(result, *cloneScenario(scenario))
	}
	return result
}

func (m *Manager) getCachedScenario(id uuid.UUID) *Scenario {
	m.cacheMu.RLock()
	defer m.cacheMu.RUnlock()
	if scenario, ok := m.cache[id]; ok {
		return cloneScenario(scenario)
	}
	return nil
}

func (m *Manager) cacheScenario(scenario *Scenario) {
	if !m.cacheEnabled() || scenario == nil {
		return
	}
	m.cacheMu.Lock()
	if m.cache == nil {
		m.cache = make(map[uuid.UUID]*Scenario)
	}
	m.cache[scenario.ID] = cloneScenario(scenario)
	m.cacheExp = time.Now().Add(m.cacheTTL)
	m.cacheMu.Unlock()
}

func (m *Manager) backfillCache(items []Scenario) {
	if !m.cacheEnabled() {
		return
	}
	m.cacheMu.Lock()
	if m.cache == nil {
		m.cache = make(map[uuid.UUID]*Scenario, len(items))
	}
	for idx := range items {
		item := items[idx]
		m.cache[item.ID] = cloneScenario(&item)
	}
	m.cacheExp = time.Now().Add(m.cacheTTL)
	m.cacheMu.Unlock()
}

func (m *Manager) removeCachedScenario(id uuid.UUID) {
	if !m.cacheEnabled() {
		return
	}
	m.cacheMu.Lock()
	delete(m.cache, id)
	m.cacheMu.Unlock()
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
	if in.RequiredLabels != nil {
		cp.RequiredLabels = append([]string(nil), in.RequiredLabels...)
	}
	if in.Dependencies != nil {
		cp.Dependencies = append([]uuid.UUID(nil), in.Dependencies...)
	}
	if in.Steps != nil {
		cp.Steps = make([]ScenarioStep, len(in.Steps))
		for idx, step := range in.Steps {
			cp.Steps[idx] = step
			if step.Args != nil {
				cp.Steps[idx].Args = copyMap(step.Args)
			}
			if step.Capabilities != nil {
				cp.Steps[idx].Capabilities = append([]string(nil), step.Capabilities...)
			}
			if step.DependsOn != nil {
				cp.Steps[idx].DependsOn = append([]string(nil), step.DependsOn...)
			}
		}
	}
	if len(in.ApprovalPolicy) > 0 {
		cp.ApprovalPolicy = append([]ApprovalRule(nil), in.ApprovalPolicy...)
	}
	return &cp
}
