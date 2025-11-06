package templates

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"log/slog"

	"github.com/m-sec-org/d-eyes/server/internal/model"
	"github.com/m-sec-org/d-eyes/server/internal/store"
)

// TaskEnqueuer 抽象调度器任务入队能力，避免循环依赖。
type TaskEnqueuer interface {
	EnqueueTask(ctx context.Context, task *model.Task) error
}

// Config 配置模板持久化等行为。
type Config struct {
	PersistPath string
}

// Manager 负责模板的管理与调度。
type Manager struct {
	mu        sync.RWMutex
	templates map[uuid.UUID]*Template
	cfg       Config
	store     store.Store
	enqueuer  TaskEnqueuer
	log       *slog.Logger
	ctx       context.Context
	cancel    context.CancelFunc
}

// Template 描述任务模板。
type Template struct {
	ID          uuid.UUID         `json:"id"`
	Name        string            `json:"name"`
	Description string            `json:"description,omitempty"`
	TaskType    string            `json:"task_type"`
	Profile     string            `json:"profile,omitempty"`
	Flags       map[string]any    `json:"flags,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
	Targets     []string          `json:"targets,omitempty"`
	Priority    int               `json:"priority,omitempty"`
	CreatedBy   string            `json:"created_by,omitempty"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
	Schedule    *Schedule         `json:"schedule,omitempty"`
}

// Schedule 描述简单的间隔调度配置。
type Schedule struct {
	Enabled         bool      `json:"enabled"`
	IntervalMinutes int       `json:"interval_minutes"`
	Targets         []string  `json:"targets,omitempty"`
	Priority        int       `json:"priority,omitempty"`
	NextRun         time.Time `json:"next_run,omitempty"`
	LastRun         time.Time `json:"last_run,omitempty"`
}

// DeployResult 返回任务下发的结果。
type DeployResult struct {
	TaskIDs []uuid.UUID `json:"task_ids"`
}

// DeployRequest 描述一次下发操作的可覆写字段。
type DeployRequest struct {
	Name        string            `json:"name,omitempty"`
	Description string            `json:"description,omitempty"`
	Profile     string            `json:"profile,omitempty"`
	Flags       map[string]any    `json:"flags,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
	Targets     []string          `json:"targets,omitempty"`
	Priority    *int              `json:"priority,omitempty"`
	CreatedBy   string            `json:"created_by,omitempty"`
}

// NewManager 构造模板管理器。
func NewManager(cfg Config, store store.Store, enqueuer TaskEnqueuer, log *slog.Logger) (*Manager, error) {
	if store == nil {
		return nil, errors.New("templates: store is nil")
	}
	if enqueuer == nil {
		return nil, errors.New("templates: enqueuer is nil")
	}
	ctx, cancel := context.WithCancel(context.Background())
	m := &Manager{
		templates: make(map[uuid.UUID]*Template),
		cfg:       cfg,
		store:     store,
		enqueuer:  enqueuer,
		log:       log,
		ctx:       ctx,
		cancel:    cancel,
	}
	if err := m.loadFromDisk(); err != nil {
		return nil, err
	}
	go m.scheduleLoop()
	return m, nil
}

// Close 结束调度循环。
func (m *Manager) Close() {
	m.cancel()
}

// CreateTemplate 新建模板。
func (m *Manager) CreateTemplate(ctx context.Context, tmpl Template) (*Template, error) {
	if strings.TrimSpace(tmpl.Name) == "" {
		return nil, errors.New("template name required")
	}
	if strings.TrimSpace(tmpl.TaskType) == "" {
		return nil, errors.New("template task_type required")
	}

	now := time.Now().UTC()
	tmpl.ID = uuid.New()
	tmpl.CreatedAt = now
	tmpl.UpdatedAt = now
	if tmpl.Schedule != nil {
		normalizeSchedule(tmpl.Schedule, now)
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.templates[tmpl.ID] = cloneTemplate(&tmpl)
	if err := m.persistLocked(); err != nil {
		return nil, err
	}
	return cloneTemplate(&tmpl), nil
}

// UpdateTemplate 覆写模板。
func (m *Manager) UpdateTemplate(ctx context.Context, id uuid.UUID, update Template) (*Template, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	current, ok := m.templates[id]
	if !ok {
		return nil, os.ErrNotExist
	}
	if strings.TrimSpace(update.Name) == "" {
		return nil, errors.New("template name required")
	}
	if strings.TrimSpace(update.TaskType) == "" {
		return nil, errors.New("template task_type required")
	}

	update.ID = id
	update.CreatedAt = current.CreatedAt
	update.UpdatedAt = time.Now().UTC()
	if update.Schedule != nil {
		normalizeSchedule(update.Schedule, update.UpdatedAt)
	}
	m.templates[id] = cloneTemplate(&update)
	if err := m.persistLocked(); err != nil {
		return nil, err
	}
	return cloneTemplate(&update), nil
}

// DeleteTemplate 删除模板。
func (m *Manager) DeleteTemplate(ctx context.Context, id uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.templates[id]; !ok {
		return os.ErrNotExist
	}
	delete(m.templates, id)
	return m.persistLocked()
}

// GetTemplate 返回单个模板。
func (m *Manager) GetTemplate(ctx context.Context, id uuid.UUID) (*Template, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	tmpl, ok := m.templates[id]
	if !ok {
		return nil, os.ErrNotExist
	}
	return cloneTemplate(tmpl), nil
}

// ListTemplates 返回模板列表。
func (m *Manager) ListTemplates(ctx context.Context) ([]Template, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]Template, 0, len(m.templates))
	for _, tmpl := range m.templates {
		result = append(result, *cloneTemplate(tmpl))
	}
	return result, nil
}

// DeployTemplate 根据模板下发任务。
func (m *Manager) DeployTemplate(ctx context.Context, id uuid.UUID, req DeployRequest) (DeployResult, error) {
	m.mu.Lock()
	tmpl, ok := m.templates[id]
	if !ok {
		m.mu.Unlock()
		return DeployResult{}, os.ErrNotExist
	}
	clone := cloneTemplate(tmpl)
	m.mu.Unlock()

	targets := req.Targets
	if len(targets) == 0 {
		targets = clone.Targets
	}

	flags := mergeAnyMap(clone.Flags, req.Flags)
	metadata := mergeStringMap(clone.Metadata, req.Metadata)
	if metadata == nil {
		metadata = make(map[string]string)
	}
	metadata["template_id"] = clone.ID.String()
	metadata["template_name"] = clone.Name
	if len(targets) > 0 {
		metadata["target_agents"] = strings.Join(targets, ",")
	}

	profile := clone.Profile
	if strings.TrimSpace(req.Profile) != "" {
		profile = req.Profile
	}

	payload := map[string]any{}
	if len(flags) > 0 {
		payload["flags"] = flags
	}
	if profile != "" {
		payload["profile"] = profile
	}
	if req.Name != "" {
		payload["name"] = req.Name
	}
	if strings.TrimSpace(req.Description) != "" {
		metadata["description_override"] = req.Description
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return DeployResult{}, err
	}

	priority := clone.Priority
	if req.Priority != nil {
		priority = *req.Priority
	}

	task := &model.Task{
		ID:        uuid.New(),
		Type:      model.TaskType(clone.TaskType),
		Profile:   profile,
		Priority:  priority,
		Payload:   payloadBytes,
		Metadata:  metadata,
		CreatedBy: chooseNonEmpty(req.CreatedBy, clone.CreatedBy),
		Status:    model.TaskStatusPending,
		CreatedAt: time.Now().UTC(),
	}

	if err := m.store.CreateTask(ctx, task); err != nil {
		return DeployResult{}, fmt.Errorf("create task: %w", err)
	}
	if err := m.enqueuer.EnqueueTask(ctx, task); err != nil {
		return DeployResult{}, fmt.Errorf("enqueue task: %w", err)
	}

	if err := m.updateScheduleAfterDeploy(id); err != nil {
		return DeployResult{}, err
	}
	return DeployResult{TaskIDs: []uuid.UUID{task.ID}}, nil
}

func (m *Manager) updateScheduleAfterDeploy(id uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	tmpl, ok := m.templates[id]
	if !ok || tmpl.Schedule == nil || !tmpl.Schedule.Enabled {
		return nil
	}
	tmpl.Schedule.LastRun = time.Now().UTC()
	if tmpl.Schedule.IntervalMinutes > 0 {
		tmpl.Schedule.NextRun = tmpl.Schedule.LastRun.Add(time.Duration(tmpl.Schedule.IntervalMinutes) * time.Minute)
	}
	return m.persistLocked()
}

func (m *Manager) scheduleLoop() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			m.runDueSchedules()
		}
	}
}

func (m *Manager) runDueSchedules() {
	now := time.Now().UTC()
	var due []*Template

	m.mu.RLock()
	for _, tmpl := range m.templates {
		if tmpl.Schedule == nil || !tmpl.Schedule.Enabled || tmpl.Schedule.IntervalMinutes <= 0 {
			continue
		}
		if tmpl.Schedule.NextRun.IsZero() || !tmpl.Schedule.NextRun.After(now) {
			due = append(due, cloneTemplate(tmpl))
		}
	}
	m.mu.RUnlock()

	for _, tmpl := range due {
		_, err := m.DeployTemplate(m.ctx, tmpl.ID, DeployRequest{
			Targets:   tmpl.Schedule.Targets,
			Priority:  &tmpl.Schedule.Priority,
			CreatedBy: "scheduler",
		})
		if err != nil && m.log != nil {
			m.log.Error("failed to deploy scheduled template", "template_id", tmpl.ID.String(), "error", err)
		}
	}
}

func (m *Manager) loadFromDisk() error {
	if strings.TrimSpace(m.cfg.PersistPath) == "" {
		return nil
	}
	data, err := os.ReadFile(m.cfg.PersistPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var persisted []*Template
	if err := json.Unmarshal(data, &persisted); err != nil {
		return err
	}
	for _, tmpl := range persisted {
		m.templates[tmpl.ID] = cloneTemplate(tmpl)
	}
	return nil
}

func (m *Manager) persistLocked() error {
	if strings.TrimSpace(m.cfg.PersistPath) == "" {
		return nil
	}
	dir := filepath.Dir(m.cfg.PersistPath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	entries := make([]*Template, 0, len(m.templates))
	for _, tmpl := range m.templates {
		entries = append(entries, cloneTemplate(tmpl))
	}
	data, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return err
	}
	tmp := m.cfg.PersistPath + ".tmp"
	if err := os.WriteFile(tmp, data, 0o640); err != nil {
		return err
	}
	return os.Rename(tmp, m.cfg.PersistPath)
}

func cloneTemplate(tmpl *Template) *Template {
	if tmpl == nil {
		return nil
	}
	clone := *tmpl
	if len(tmpl.Flags) > 0 {
		clone.Flags = make(map[string]any, len(tmpl.Flags))
		for k, v := range tmpl.Flags {
			clone.Flags[k] = v
		}
	}
	if len(tmpl.Metadata) > 0 {
		clone.Metadata = make(map[string]string, len(tmpl.Metadata))
		for k, v := range tmpl.Metadata {
			clone.Metadata[k] = v
		}
	}
	if len(tmpl.Targets) > 0 {
		clone.Targets = append([]string(nil), tmpl.Targets...)
	}
	if tmpl.Schedule != nil {
		sched := *tmpl.Schedule
		if len(tmpl.Schedule.Targets) > 0 {
			sched.Targets = append([]string(nil), tmpl.Schedule.Targets...)
		}
		clone.Schedule = &sched
	}
	return &clone
}

func mergeAnyMap(base, override map[string]any) map[string]any {
	if len(base) == 0 && len(override) == 0 {
		return nil
	}
	merged := make(map[string]any, len(base)+len(override))
	for k, v := range base {
		merged[k] = v
	}
	for k, v := range override {
		if v == nil {
			delete(merged, k)
			continue
		}
		merged[k] = v
	}
	return merged
}

func mergeStringMap(base, override map[string]string) map[string]string {
	if len(base) == 0 && len(override) == 0 {
		return nil
	}
	merged := make(map[string]string, len(base)+len(override))
	for k, v := range base {
		merged[k] = v
	}
	for k, v := range override {
		if strings.TrimSpace(v) == "" {
			delete(merged, k)
			continue
		}
		merged[k] = v
	}
	return merged
}

func normalizeSchedule(s *Schedule, now time.Time) {
	if s == nil {
		return
	}
	if s.IntervalMinutes <= 0 {
		s.IntervalMinutes = 0
		s.Enabled = false
		s.NextRun = time.Time{}
		return
	}
	if s.NextRun.IsZero() {
		s.NextRun = now.Add(time.Duration(s.IntervalMinutes) * time.Minute)
	}
}

func chooseNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
