package taskcatalog

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"log/slog"
)

// Config controls how the catalog persists data.
type Config struct {
	PersistPath string
}

// Manager persists task types + profile schemas for validation.
type Manager struct {
	mu           sync.RWMutex
	taskTypes    map[string]*TaskType
	taskProfiles map[string]*TaskProfile
	persistPath  string
	log          *slog.Logger
}

// TaskType describes a task category exposed to operators.
type TaskType struct {
	Name         string    `json:"name"`
	DisplayName  string    `json:"display_name"`
	Description  string    `json:"description,omitempty"`
	Capabilities []string  `json:"capabilities,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// TaskProfile is a versioned profile schema for a task type.
type TaskProfile struct {
	ID          string            `json:"id"`
	TaskType    string            `json:"task_type"`
	DisplayName string            `json:"display_name"`
	Version     string            `json:"version"`
	Description string            `json:"description,omitempty"`
	Owner       string            `json:"owner,omitempty"`
	Schema      TaskProfileSchema `json:"schema"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
}

// TaskProfileSchema defines how payload parameters are validated.
type TaskProfileSchema struct {
	Defaults    map[string]any      `json:"defaults,omitempty"`
	Parameters  []ProfileParameter  `json:"parameters"`
	Constraints []ProfileConstraint `json:"constraints,omitempty"`
}

// ProfileParameter represents a single configurable parameter.
type ProfileParameter struct {
	Key      string   `json:"key"`
	Label    string   `json:"label"`
	Type     string   `json:"type"`
	Required bool     `json:"required,omitempty"`
	Options  []string `json:"options,omitempty"`
	Pattern  string   `json:"pattern,omitempty"`
	Format   string   `json:"format,omitempty"`
	Min      *float64 `json:"min,omitempty"`
	Max      *float64 `json:"max,omitempty"`
	Default  any      `json:"default,omitempty"`
	Hint     string   `json:"hint,omitempty"`
}

// ProfileConstraint provides informational validation hints.
type ProfileConstraint struct {
	Expression string `json:"expression"`
	Message    string `json:"message"`
}

type persistPayload struct {
	TaskTypes    []*TaskType    `json:"task_types"`
	TaskProfiles []*TaskProfile `json:"task_profiles"`
}

var (
	ErrUnknownTaskType = errors.New("task catalog: unknown task type")
	ErrUnknownProfile  = errors.New("task catalog: unknown profile")
)

// NewManager creates a task catalog and optionally loads persisted state.
func NewManager(cfg Config, log *slog.Logger) (*Manager, error) {
	m := &Manager{
		taskTypes:    make(map[string]*TaskType),
		taskProfiles: make(map[string]*TaskProfile),
		persistPath:  cfg.PersistPath,
		log:          log,
	}
	if cfg.PersistPath != "" {
		if err := m.load(); err != nil {
			return nil, err
		}
	}
	return m, nil
}

// ListTaskTypes returns all registered task types sorted by name.
func (m *Manager) ListTaskTypes(ctx context.Context) ([]TaskType, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]TaskType, 0, len(m.taskTypes))
	for _, item := range m.taskTypes {
		result = append(result, *cloneTaskType(item))
	}
	sort.Slice(result, func(i, j int) bool {
		return strings.ToLower(result[i].Name) < strings.ToLower(result[j].Name)
	})
	return result, ctx.Err()
}

// GetTaskType fetches a task type by name.
func (m *Manager) GetTaskType(_ context.Context, name string) (*TaskType, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if item, ok := m.taskTypes[strings.ToLower(name)]; ok {
		return cloneTaskType(item), nil
	}
	return nil, ErrUnknownTaskType
}

// CreateTaskType registers a new task type.
func (m *Manager) CreateTaskType(_ context.Context, typ TaskType) (*TaskType, error) {
	if err := validateTaskTypeInput(typ); err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	typ.CreatedAt = now
	typ.UpdatedAt = now

	key := strings.ToLower(typ.Name)

	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.taskTypes[key]; exists {
		return nil, fmt.Errorf("task catalog: type %s already exists", typ.Name)
	}
	m.taskTypes[key] = cloneTaskType(&typ)
	if err := m.persistLocked(); err != nil {
		return nil, err
	}
	return cloneTaskType(&typ), nil
}

// UpdateTaskType replaces metadata for an existing task type.
func (m *Manager) UpdateTaskType(_ context.Context, name string, update TaskType) (*TaskType, error) {
	if err := validateTaskTypeInput(update); err != nil {
		return nil, err
	}
	key := strings.ToLower(name)
	m.mu.Lock()
	defer m.mu.Unlock()
	current, ok := m.taskTypes[key]
	if !ok {
		return nil, ErrUnknownTaskType
	}
	update.Name = current.Name // name is immutable
	update.CreatedAt = current.CreatedAt
	update.UpdatedAt = time.Now().UTC()
	m.taskTypes[key] = cloneTaskType(&update)
	if err := m.persistLocked(); err != nil {
		return nil, err
	}
	return cloneTaskType(&update), nil
}

// DeleteTaskType removes a task type if no profiles depend on it.
func (m *Manager) DeleteTaskType(_ context.Context, name string) error {
	key := strings.ToLower(name)
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.taskTypes[key]; !ok {
		return ErrUnknownTaskType
	}
	for _, profile := range m.taskProfiles {
		if strings.EqualFold(profile.TaskType, name) {
			return fmt.Errorf("task catalog: task type %s still referenced by profile %s", name, profile.ID)
		}
	}
	delete(m.taskTypes, key)
	return m.persistLocked()
}

// ListTaskProfiles returns profiles, optionally filtered by task type.
func (m *Manager) ListTaskProfiles(ctx context.Context, taskType string) ([]TaskProfile, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]TaskProfile, 0, len(m.taskProfiles))
	for _, profile := range m.taskProfiles {
		if taskType != "" && !strings.EqualFold(profile.TaskType, taskType) {
			continue
		}
		result = append(result, *cloneTaskProfile(profile))
	}
	sort.Slice(result, func(i, j int) bool {
		return strings.ToLower(result[i].ID) < strings.ToLower(result[j].ID)
	})
	return result, ctx.Err()
}

// GetTaskProfile fetches a profile by ID.
func (m *Manager) GetTaskProfile(_ context.Context, id string) (*TaskProfile, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if profile, ok := m.taskProfiles[id]; ok {
		return cloneTaskProfile(profile), nil
	}
	return nil, ErrUnknownProfile
}

// CreateTaskProfile registers a profile schema against a type.
func (m *Manager) CreateTaskProfile(_ context.Context, profile TaskProfile) (*TaskProfile, error) {
	normalizeTaskProfileNumericDefaults(&profile)
	if err := validateTaskProfileInput(profile); err != nil {
		return nil, err
	}
	if profile.ID == "" {
		profile.ID = uuid.NewString()
	}
	now := time.Now().UTC()
	profile.CreatedAt = now
	profile.UpdatedAt = now

	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.taskTypes[strings.ToLower(profile.TaskType)]; !ok {
		return nil, ErrUnknownTaskType
	}
	if _, exists := m.taskProfiles[profile.ID]; exists {
		return nil, fmt.Errorf("task catalog: profile %s already exists", profile.ID)
	}
	cp := cloneTaskProfile(&profile)
	m.taskProfiles[profile.ID] = cp
	if err := m.persistLocked(); err != nil {
		return nil, err
	}
	return cloneTaskProfile(cp), nil
}

// UpdateTaskProfile replaces schema metadata.
func (m *Manager) UpdateTaskProfile(_ context.Context, id string, profile TaskProfile) (*TaskProfile, error) {
	normalizeTaskProfileNumericDefaults(&profile)
	if err := validateTaskProfileInput(profile); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	current, ok := m.taskProfiles[id]
	if !ok {
		return nil, ErrUnknownProfile
	}
	if _, ok := m.taskTypes[strings.ToLower(profile.TaskType)]; !ok {
		return nil, ErrUnknownTaskType
	}
	profile.ID = id
	profile.CreatedAt = current.CreatedAt
	profile.UpdatedAt = time.Now().UTC()
	cp := cloneTaskProfile(&profile)
	m.taskProfiles[id] = cp
	if err := m.persistLocked(); err != nil {
		return nil, err
	}
	return cloneTaskProfile(cp), nil
}

// DeleteTaskProfile removes a profile by ID.
func (m *Manager) DeleteTaskProfile(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.taskProfiles[id]; !ok {
		return ErrUnknownProfile
	}
	delete(m.taskProfiles, id)
	return m.persistLocked()
}

// ValidateTaskPayload ensures payload satisfies the profile schema.
func (m *Manager) ValidateTaskPayload(taskType, profileID string, payload map[string]any) error {
	m.mu.RLock()
	profile, ok := m.taskProfiles[profileID]
	m.mu.RUnlock()
	if !ok {
		return ErrUnknownProfile
	}
	if !strings.EqualFold(profile.TaskType, taskType) {
		return fmt.Errorf("task catalog: profile %s belongs to task type %s", profile.ID, profile.TaskType)
	}
	return validatePayloadAgainstSchema(profile.Schema, payload)
}

func validateTaskTypeInput(typ TaskType) error {
	if strings.TrimSpace(typ.Name) == "" {
		return errors.New("task catalog: task type name required")
	}
	if strings.TrimSpace(typ.DisplayName) == "" {
		return errors.New("task catalog: display_name required")
	}
	return nil
}

func validateTaskProfileInput(profile TaskProfile) error {
	if strings.TrimSpace(profile.TaskType) == "" {
		return errors.New("task catalog: profile task_type required")
	}
	if strings.TrimSpace(profile.DisplayName) == "" {
		return errors.New("task catalog: profile display_name required")
	}
	if strings.TrimSpace(profile.Version) == "" {
		return errors.New("task catalog: profile version required")
	}
	if len(profile.Schema.Parameters) == 0 {
		return errors.New("task catalog: profile schema parameters required")
	}
	for _, param := range profile.Schema.Parameters {
		if err := validateParameterDefinition(param); err != nil {
			return err
		}
		if param.Default != nil {
			if err := validateParameterValue(param, param.Default); err != nil {
				return fmt.Errorf("parameter %s default invalid: %w", param.Key, err)
			}
		}
	}
	for key, value := range profile.Schema.Defaults {
		if param, ok := findParameter(profile.Schema.Parameters, key); ok {
			if err := validateParameterValue(param, value); err != nil {
				return fmt.Errorf("default %s invalid: %w", key, err)
			}
		}
	}
	return nil
}

func validateParameterDefinition(param ProfileParameter) error {
	if strings.TrimSpace(param.Key) == "" {
		return errors.New("task catalog: parameter key required")
	}
	if strings.TrimSpace(param.Label) == "" {
		return fmt.Errorf("task catalog: parameter %s label required", param.Key)
	}
	switch param.Type {
	case "string", "number", "boolean", "enum", "multiselect", "string_list", "cidr_list":
	default:
		return fmt.Errorf("task catalog: parameter %s has unsupported type %s", param.Key, param.Type)
	}
	if (param.Type == "enum" || param.Type == "multiselect") && len(param.Options) == 0 {
		return fmt.Errorf("task catalog: parameter %s options required", param.Key)
	}
	return nil
}

func findParameter(params []ProfileParameter, key string) (ProfileParameter, bool) {
	for _, p := range params {
		if p.Key == key {
			return p, true
		}
	}
	return ProfileParameter{}, false
}

func validatePayloadAgainstSchema(schema TaskProfileSchema, payload map[string]any) error {
	var errs []string
	normalized := map[string]any{}
	for k, v := range payload {
		normalized[k] = v
	}

	for _, param := range schema.Parameters {
		val, exists := normalized[param.Key]
		if !exists {
			if param.Required {
				if _, ok := resolveDefault(schema, param); !ok {
					errs = append(errs, fmt.Sprintf("missing required parameter %s", param.Key))
				}
			}
			continue
		}
		if err := validateParameterValue(param, val); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

func resolveDefault(schema TaskProfileSchema, param ProfileParameter) (any, bool) {
	if param.Default != nil {
		return param.Default, true
	}
	if schema.Defaults == nil {
		return nil, false
	}
	value, ok := schema.Defaults[param.Key]
	return value, ok
}

func validateParameterValue(param ProfileParameter, value any) error {
	switch param.Type {
	case "string":
		str, ok := toString(value)
		if !ok {
			return fmt.Errorf("%s expects string", param.Key)
		}
		if param.Pattern != "" {
			re, err := regexp.Compile(param.Pattern)
			if err != nil {
				return fmt.Errorf("%s invalid regex pattern: %w", param.Key, err)
			}
			if !re.MatchString(str) {
				return fmt.Errorf("%s fails pattern validation", param.Key)
			}
		}
	case "number":
		num, ok := toFloat(value)
		if !ok {
			return fmt.Errorf("%s expects number", param.Key)
		}
		if param.Min != nil && num < *param.Min {
			return fmt.Errorf("%s must be >= %v", param.Key, *param.Min)
		}
		if param.Max != nil && num > *param.Max {
			return fmt.Errorf("%s must be <= %v", param.Key, *param.Max)
		}
	case "boolean":
		if _, ok := value.(bool); !ok {
			return fmt.Errorf("%s expects boolean", param.Key)
		}
	case "enum":
		str, ok := toString(value)
		if !ok {
			return fmt.Errorf("%s expects string enum", param.Key)
		}
		if !contains(param.Options, str) {
			return fmt.Errorf("%s value %s not in options", param.Key, str)
		}
	case "multiselect", "string_list":
		stringsVal, ok := toStringSlice(value)
		if !ok {
			return fmt.Errorf("%s expects string list", param.Key)
		}
		if param.Type == "multiselect" {
			for _, v := range stringsVal {
				if !contains(param.Options, v) {
					return fmt.Errorf("%s value %s not in options", param.Key, v)
				}
			}
		}
	case "cidr_list":
		slice, ok := toStringSlice(value)
		if !ok {
			return fmt.Errorf("%s expects CIDR list", param.Key)
		}
		for _, cidr := range slice {
			if strings.TrimSpace(cidr) == "" {
				return fmt.Errorf("%s CIDR cannot be empty", param.Key)
			}
			if _, _, err := net.ParseCIDR(strings.TrimSpace(cidr)); err != nil {
				return fmt.Errorf("%s invalid CIDR %s", param.Key, cidr)
			}
		}
	}
	return nil
}

func toString(value any) (string, bool) {
	switch v := value.(type) {
	case string:
		return v, true
	}
	return "", false
}

func toFloat(value any) (float64, bool) {
	switch v := value.(type) {
	case float64:
		if math.IsNaN(v) || math.IsInf(v, 0) {
			return 0, false
		}
		return v, true
	case float32:
		return float64(v), true
	case int:
		return float64(v), true
	case int64:
		return float64(v), true
	case json.Number:
		f, err := v.Float64()
		if err != nil {
			return 0, false
		}
		return f, true
	}
	return 0, false
}

func toStringSlice(value any) ([]string, bool) {
	switch v := value.(type) {
	case []string:
		return v, true
	case []any:
		result := make([]string, 0, len(v))
		for _, item := range v {
			str, ok := toString(item)
			if !ok {
				return nil, false
			}
			result = append(result, str)
		}
		return result, true
	default:
		return nil, false
	}
}

func contains(options []string, value string) bool {
	for _, opt := range options {
		if opt == value {
			return true
		}
	}
	return false
}

func cloneTaskType(t *TaskType) *TaskType {
	if t == nil {
		return nil
	}
	cp := *t
	if t.Capabilities != nil {
		cp.Capabilities = append([]string(nil), t.Capabilities...)
	}
	return &cp
}

func cloneTaskProfile(p *TaskProfile) *TaskProfile {
	if p == nil {
		return nil
	}
	cp := *p
	cp.Schema = cloneSchema(p.Schema)
	return &cp
}

func cloneSchema(s TaskProfileSchema) TaskProfileSchema {
	out := TaskProfileSchema{}
	if s.Defaults != nil {
		out.Defaults = make(map[string]any, len(s.Defaults))
		for k, v := range s.Defaults {
			out.Defaults[k] = v
		}
	}
	if s.Parameters != nil {
		out.Parameters = make([]ProfileParameter, len(s.Parameters))
		copy(out.Parameters, s.Parameters)
	}
	if s.Constraints != nil {
		out.Constraints = make([]ProfileConstraint, len(s.Constraints))
		copy(out.Constraints, s.Constraints)
	}
	return out
}

func (m *Manager) persistLocked() error {
	if m.persistPath == "" {
		return nil
	}
	payload := persistPayload{
		TaskTypes:    make([]*TaskType, 0, len(m.taskTypes)),
		TaskProfiles: make([]*TaskProfile, 0, len(m.taskProfiles)),
	}
	for _, tt := range m.taskTypes {
		payload.TaskTypes = append(payload.TaskTypes, cloneTaskType(tt))
	}
	for _, prof := range m.taskProfiles {
		payload.TaskProfiles = append(payload.TaskProfiles, cloneTaskProfile(prof))
	}
	sort.Slice(payload.TaskTypes, func(i, j int) bool {
		return strings.ToLower(payload.TaskTypes[i].Name) < strings.ToLower(payload.TaskTypes[j].Name)
	})
	sort.Slice(payload.TaskProfiles, func(i, j int) bool {
		return strings.ToLower(payload.TaskProfiles[i].ID) < strings.ToLower(payload.TaskProfiles[j].ID)
	})
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(m.persistPath), 0o755); err != nil {
		return err
	}
	tmp := m.persistPath + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, m.persistPath)
}

func (m *Manager) load() error {
	data, err := os.ReadFile(m.persistPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	var payload persistPayload
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(&payload); err != nil {
		return fmt.Errorf("task catalog: invalid persist file: %w", err)
	}
	for _, tt := range payload.TaskTypes {
		key := strings.ToLower(tt.Name)
		m.taskTypes[key] = cloneTaskType(tt)
	}
	for _, prof := range payload.TaskProfiles {
		normalizeTaskProfileNumericDefaults(prof)
		m.taskProfiles[prof.ID] = cloneTaskProfile(prof)
	}
	return nil
}
