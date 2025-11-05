package store

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/m-sec-org/d-eyes/server/internal/model"
)

type memoryStore struct {
	mu           sync.RWMutex
	agents       map[uuid.UUID]*model.Agent
	agentsByName map[string]uuid.UUID
	tasks        map[uuid.UUID]*model.Task
	taskRuns     map[uuid.UUID]*model.TaskRun
	leases       map[uuid.UUID]uuid.UUID
	artifacts    map[uuid.UUID]model.Artifact
}

func newMemoryStore() Store {
	return &memoryStore{
		agents:       make(map[uuid.UUID]*model.Agent),
		agentsByName: make(map[string]uuid.UUID),
		tasks:        make(map[uuid.UUID]*model.Task),
		taskRuns:     make(map[uuid.UUID]*model.TaskRun),
		leases:       make(map[uuid.UUID]uuid.UUID),
		artifacts:    make(map[uuid.UUID]model.Artifact),
	}
}

func (m *memoryStore) UpsertAgent(_ context.Context, agent *model.Agent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if agent.ID == uuid.Nil {
		agent.ID = uuid.New()
	}
	agentCopy := *agent
	agentCopy.CreatedAt = nowIfZero(agentCopy.CreatedAt)
	agentCopy.UpdatedAt = time.Now()
	m.agents[agentCopy.ID] = &agentCopy
	if agentCopy.Name != "" {
		m.agentsByName[agentCopy.Name] = agentCopy.ID
	}
	return nil
}

func (m *memoryStore) GetAgentByName(_ context.Context, name string) (*model.Agent, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if id, ok := m.agentsByName[name]; ok {
		if agent, ok := m.agents[id]; ok {
			cp := *agent
			return &cp, nil
		}
	}
	return nil, ErrNotFound
}

func (m *memoryStore) GetAgent(_ context.Context, id uuid.UUID) (*model.Agent, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	agent, ok := m.agents[id]
	if !ok {
		return nil, ErrNotFound
	}
	cp := *agent
	return &cp, nil
}

func (m *memoryStore) UpdateAgentStatus(_ context.Context, id uuid.UUID, status model.AgentStatus, heartbeat time.Time, load float64, running []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	agent, ok := m.agents[id]
	if !ok {
		return ErrNotFound
	}
	agent.Status = status
	agent.LastHeartbeat = heartbeat
	agent.UpdatedAt = time.Now()
	agent.Capabilities = append([]string(nil), agent.Capabilities...)
	agent.Version = agent.Version
	agent.Platform = agent.Platform
	_ = load
	_ = running
	return nil
}

func (m *memoryStore) CreateTask(_ context.Context, task *model.Task) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if task.ID == uuid.Nil {
		task.ID = uuid.New()
	}
	now := time.Now()
	taskCopy := *task
	taskCopy.CreatedAt = now
	taskCopy.UpdatedAt = now
	m.tasks[taskCopy.ID] = &taskCopy
	return nil
}

func (m *memoryStore) UpdateTaskStatus(_ context.Context, taskID uuid.UUID, status model.TaskStatus) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	task, ok := m.tasks[taskID]
	if !ok {
		return ErrNotFound
	}
	task.Status = status
	task.UpdatedAt = time.Now()
	return nil
}

func (m *memoryStore) IncrementTaskRetry(_ context.Context, taskID uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	task, ok := m.tasks[taskID]
	if !ok {
		return ErrNotFound
	}
	task.RetryCount++
	task.UpdatedAt = time.Now()
	return nil
}

func (m *memoryStore) GetTask(_ context.Context, id uuid.UUID) (*model.Task, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	task, ok := m.tasks[id]
	if !ok {
		return nil, ErrNotFound
	}
	cp := *task
	cp.Metadata = copyMap(task.Metadata)
	cp.Payload = append([]byte(nil), task.Payload...)
	return &cp, nil
}

func (m *memoryStore) ListPendingTasks(_ context.Context, limit int) ([]*model.Task, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	res := make([]*model.Task, 0, limit)
	for _, task := range m.tasks {
		if task.Status == model.TaskStatusPending {
			cp := *task
			cp.Metadata = copyMap(task.Metadata)
			cp.Payload = append([]byte(nil), task.Payload...)
			res = append(res, &cp)
			if limit > 0 && len(res) >= limit {
				break
			}
		}
	}
	return res, nil
}

func (m *memoryStore) ListTasks(_ context.Context, statuses []model.TaskStatus, limit int) ([]*model.Task, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	filter := make(map[model.TaskStatus]struct{}, len(statuses))
	for _, st := range statuses {
		filter[st] = struct{}{}
	}
	res := make([]*model.Task, 0, len(m.tasks))
	for _, task := range m.tasks {
		if len(filter) > 0 {
			if _, ok := filter[task.Status]; !ok {
				continue
			}
		}
		cp := *task
		cp.Metadata = copyMap(task.Metadata)
		cp.Payload = append([]byte(nil), task.Payload...)
		res = append(res, &cp)
	}
	sort.Slice(res, func(i, j int) bool {
		if res[i].CreatedAt.Equal(res[j].CreatedAt) {
			return res[i].ID.String() < res[j].ID.String()
		}
		return res[i].CreatedAt.After(res[j].CreatedAt)
	})
	if limit > 0 && len(res) > limit {
		res = res[:limit]
	}
	return res, nil
}

func (m *memoryStore) CreateTaskRun(_ context.Context, run *model.TaskRun) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if run.ID == uuid.Nil {
		run.ID = uuid.New()
	}
	now := time.Now()
	runCopy := *run
	if runCopy.StartedAt == nil {
		runCopy.StartedAt = ptrTime(now)
	}
	m.taskRuns[runCopy.ID] = &runCopy
	m.leases[runCopy.LeaseID] = runCopy.ID
	return nil
}

func (m *memoryStore) UpdateTaskRunStatusByLease(_ context.Context, leaseID uuid.UUID, status model.TaskStatus) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	runID, ok := m.leases[leaseID]
	if !ok {
		return ErrNotFound
	}
	run, ok := m.taskRuns[runID]
	if !ok {
		return ErrNotFound
	}
	run.Status = status
	return nil
}

func (m *memoryStore) UpdateTaskRunCompletion(_ context.Context, runID uuid.UUID, status model.TaskStatus, finished time.Time, summary []byte, errMsg string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	run, ok := m.taskRuns[runID]
	if !ok {
		return ErrNotFound
	}
	run.Status = status
	run.FinishedAt = ptrTime(finished)
	run.Summary = append([]byte(nil), summary...)
	run.ErrorMessage = errMsg
	if run.LeaseID != uuid.Nil {
		delete(m.leases, run.LeaseID)
	}
	return nil
}

func (m *memoryStore) GetTaskRunByLease(_ context.Context, leaseID uuid.UUID) (*model.TaskRun, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	runID, ok := m.leases[leaseID]
	if !ok {
		return nil, ErrNotFound
	}
	run, ok := m.taskRuns[runID]
	if !ok {
		return nil, ErrNotFound
	}
	cp := *run
	return &cp, nil
}

func (m *memoryStore) GetLatestTaskRun(_ context.Context, taskID uuid.UUID) (*model.TaskRun, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var latest *model.TaskRun
	for _, run := range m.taskRuns {
		if run.TaskID != taskID {
			continue
		}
		if latest == nil || compareRunTime(run, latest) > 0 {
			cp := *run
			latest = &cp
		}
	}
	if latest == nil {
		return nil, ErrNotFound
	}
	return latest, nil
}

func (m *memoryStore) SaveArtifacts(_ context.Context, artifacts []model.Artifact) error {
	if len(artifacts) == 0 {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, art := range artifacts {
		id := art.ID
		if id == uuid.Nil {
			id = uuid.New()
			art.ID = id
		}
		m.artifacts[id] = art
	}
	return nil
}

func copyMap(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func nowIfZero(t time.Time) time.Time {
	if t.IsZero() {
		return time.Now()
	}
	return t
}

func ptrTime(t time.Time) *time.Time {
	return &t
}

func pickRunTime(run *model.TaskRun) time.Time {
	if run.FinishedAt != nil && !run.FinishedAt.IsZero() {
		return *run.FinishedAt
	}
	if run.StartedAt != nil && !run.StartedAt.IsZero() {
		return *run.StartedAt
	}
	return run.LeaseExpires
}

func compareRunTime(a, b *model.TaskRun) int {
	at := pickRunTime(a)
	bt := pickRunTime(b)
	switch {
	case at.After(bt):
		return 1
	case at.Before(bt):
		return -1
	}
	as := a.ID.String()
	bs := b.ID.String()
	switch {
	case as > bs:
		return 1
	case as < bs:
		return -1
	default:
		return 0
	}
}

func (m *memoryStore) Ping(_ context.Context) error {
	return nil
}

func NewInMemoryStore() Store {
	return newMemoryStore()
}

var _ Store = (*memoryStore)(nil)

func (m *memoryStore) ListAgents(_ context.Context) ([]*model.Agent, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	res := make([]*model.Agent, 0, len(m.agents))
	for _, agent := range m.agents {
		cp := *agent
		if cp.Labels != nil {
			labels := make(map[string]string, len(cp.Labels))
			for k, v := range cp.Labels {
				labels[k] = v
			}
			cp.Labels = labels
		}
		if cp.Capabilities != nil {
			cp.Capabilities = append([]string(nil), cp.Capabilities...)
		}
		res = append(res, &cp)
	}
	return res, nil
}
