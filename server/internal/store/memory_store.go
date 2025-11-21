package store

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/m-sec-org/d-eyes/server/internal/model"
)

type memoryStore struct {
	mu              sync.RWMutex
	agents          map[uuid.UUID]*model.Agent
	agentsByName    map[string]uuid.UUID
	tasks           map[uuid.UUID]*model.Task
	taskRuns        map[uuid.UUID]*model.TaskRun
	leases          map[uuid.UUID]uuid.UUID
	artifacts       map[uuid.UUID]model.Artifact
	taskResults     map[uuid.UUID]*model.TaskResult
	tiSamples       map[uuid.UUID]*model.ThreatIntelSample
	tiJobs          map[uuid.UUID]*model.ThreatIntelJob
	tiVerdicts      map[uuid.UUID]*model.ThreatIntelVerdict
	behaviorMetrics []model.BehaviorMetric
	behaviorEvents  []model.BehaviorEvent
	anomalies       map[uuid.UUID]*model.Anomaly
	behaviorGraphs  map[uuid.UUID]*model.AnomalyGraph
	playbooks       map[uuid.UUID]*model.Playbook
	playbookRuns    map[uuid.UUID]*model.PlaybookRun
	frameworks      map[uuid.UUID]*model.ComplianceFramework
	controls        map[uuid.UUID]*model.ComplianceControl
	mappings        map[uuid.UUID][]model.ControlMapping
	findings        map[uuid.UUID]*model.ComplianceFinding
	basScenarios    map[uuid.UUID]*model.BASScenario
}

func newMemoryStore() Store {
	return &memoryStore{
		agents:          make(map[uuid.UUID]*model.Agent),
		agentsByName:    make(map[string]uuid.UUID),
		tasks:           make(map[uuid.UUID]*model.Task),
		taskRuns:        make(map[uuid.UUID]*model.TaskRun),
		leases:          make(map[uuid.UUID]uuid.UUID),
		artifacts:       make(map[uuid.UUID]model.Artifact),
		taskResults:     make(map[uuid.UUID]*model.TaskResult),
		tiSamples:       make(map[uuid.UUID]*model.ThreatIntelSample),
		tiJobs:          make(map[uuid.UUID]*model.ThreatIntelJob),
		tiVerdicts:      make(map[uuid.UUID]*model.ThreatIntelVerdict),
		behaviorMetrics: make([]model.BehaviorMetric, 0, 128),
		behaviorEvents:  make([]model.BehaviorEvent, 0, 128),
		anomalies:       make(map[uuid.UUID]*model.Anomaly),
		behaviorGraphs:  make(map[uuid.UUID]*model.AnomalyGraph),
		playbooks:       make(map[uuid.UUID]*model.Playbook),
		playbookRuns:    make(map[uuid.UUID]*model.PlaybookRun),
		frameworks:      make(map[uuid.UUID]*model.ComplianceFramework),
		controls:        make(map[uuid.UUID]*model.ComplianceControl),
		mappings:        make(map[uuid.UUID][]model.ControlMapping),
		findings:        make(map[uuid.UUID]*model.ComplianceFinding),
		basScenarios:    make(map[uuid.UUID]*model.BASScenario),
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

func (m *memoryStore) UpdateAgentMetadata(_ context.Context, id uuid.UUID, labels map[string]string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	agent, ok := m.agents[id]
	if !ok {
		return ErrNotFound
	}
	copyLabels := make(map[string]string, len(labels))
	for k, v := range labels {
		copyLabels[k] = v
	}
	agent.Labels = copyLabels
	agent.UpdatedAt = time.Now()
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
	if taskCopy.Metadata != nil {
		taskCopy.Metadata = copyMap(task.Metadata)
	}
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
	if task.Metadata != nil {
		task.Metadata = copyMap(task.Metadata)
	}
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
	cp.Profile = task.Profile
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
		cp.Profile = task.Profile
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
	if runCopy.TaskType == "" {
		runCopy.TaskType = model.TaskType("generic")
	}
	if runCopy.Metadata != nil {
		metaCopy := make(map[string]string, len(runCopy.Metadata))
		for k, v := range runCopy.Metadata {
			metaCopy[k] = v
		}
		runCopy.Metadata = metaCopy
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

func (m *memoryStore) UpdateTaskRunCompletion(_ context.Context, runID uuid.UUID, status model.TaskStatus, finished time.Time, summary []byte, errMsg string, metadata map[string]string, exitCode int32, errorCode string, expiresAt time.Time) error {
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
	if metadata != nil {
		metaCopy := make(map[string]string, len(metadata))
		for k, v := range metadata {
			metaCopy[k] = v
		}
		run.Metadata = metaCopy
	} else {
		run.Metadata = nil
	}
	run.ExitCode = exitCode
	run.ErrorCode = errorCode
	if !expiresAt.IsZero() {
		run.ExpiresAt = expiresAt
	}
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
	if run.Metadata != nil {
		cp.Metadata = copyMap(run.Metadata)
	}
	cp.TaskType = run.TaskType
	if !run.ExpiresAt.IsZero() {
		cp.ExpiresAt = run.ExpiresAt
	}
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
	if latest.Metadata != nil {
		meta := copyMap(latest.Metadata)
		latest.Metadata = meta
	}
	return latest, nil
}

func (m *memoryStore) ListTaskRunsByAgent(_ context.Context, agentID uuid.UUID, statuses []model.TaskStatus, limit int) ([]*model.TaskRun, error) {
	if limit <= 0 {
		limit = 100
	}
	statusSet := make(map[model.TaskStatus]struct{}, len(statuses))
	for _, st := range statuses {
		statusSet[st] = struct{}{}
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	results := make([]*model.TaskRun, 0, limit)
	for _, run := range m.taskRuns {
		if run.AgentID != agentID {
			continue
		}
		if len(statusSet) > 0 {
			if _, ok := statusSet[run.Status]; !ok {
				continue
			}
		}
		copy := *run
		if run.Metadata != nil {
			copy.Metadata = cloneMap(run.Metadata)
		}
		results = append(results, &copy)
		if len(results) >= limit {
			break
		}
	}
	sort.Slice(results, func(i, j int) bool {
		return results[i].LeaseExpires.Before(results[j].LeaseExpires)
	})
	return results, nil
}

func cloneMap(src map[string]string) map[string]string {
	if len(src) == 0 {
		return nil
	}
	copy := make(map[string]string, len(src))
	for k, v := range src {
		copy[k] = v
	}
	return copy
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

func (m *memoryStore) InsertTaskResult(ctx context.Context, result *model.TaskResult) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if result == nil {
		return nil
	}
	if result.ID == uuid.Nil {
		result.ID = uuid.New()
	}
	cp := *result
	if cp.Metadata != nil {
		meta := make(map[string]string, len(cp.Metadata))
		for k, v := range cp.Metadata {
			meta[k] = v
		}
		cp.Metadata = meta
	}
	m.taskResults[cp.ID] = &cp
	return nil
}

func (m *memoryStore) ArchiveTaskResults(ctx context.Context, before time.Time) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if before.IsZero() {
		return 0, nil
	}
	removed := 0
	for id, res := range m.taskResults {
		if res.CompletedAt.Before(before) {
			delete(m.taskResults, id)
			removed++
		}
	}
	return removed, nil
}

func (m *memoryStore) ListTaskResults(_ context.Context, taskType model.TaskType, limit int) ([]*model.TaskResult, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	results := make([]*model.TaskResult, 0, len(m.taskResults))
	for _, res := range m.taskResults {
		if taskType != "" && res.TaskType != taskType {
			continue
		}
		cp := *res
		if res.Metadata != nil {
			cp.Metadata = copyMap(res.Metadata)
		}
		if res.Summary != nil {
			cp.Summary = append([]byte(nil), res.Summary...)
		}
		results = append(results, &cp)
	}
	sort.Slice(results, func(i, j int) bool {
		if results[i].CompletedAt.Equal(results[j].CompletedAt) {
			return results[i].ID.String() > results[j].ID.String()
		}
		return results[i].CompletedAt.After(results[j].CompletedAt)
	})
	if limit > 0 && len(results) > limit {
		results = results[:limit]
	}
	return results, nil
}

func (m *memoryStore) GetArtifacts(_ context.Context, ids []uuid.UUID) ([]model.Artifact, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if len(ids) == 0 {
		return nil, nil
	}
	result := make([]model.Artifact, 0, len(ids))
	for _, id := range ids {
		art, ok := m.artifacts[id]
		if !ok {
			return nil, ErrNotFound
		}
		cp := art
		if art.Blob != nil {
			cp.Blob = append([]byte(nil), art.Blob...)
		}
		result = append(result, cp)
	}
	return result, nil
}

func (m *memoryStore) SaveBehaviorMetric(_ context.Context, metric *model.BehaviorMetric) error {
	if metric == nil {
		return errors.New("store: nil behavior metric")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if metric.ID == uuid.Nil {
		metric.ID = uuid.New()
	}
	if metric.CreatedAt.IsZero() {
		metric.CreatedAt = time.Now()
	}
	m.behaviorMetrics = append([]model.BehaviorMetric{*metric}, m.behaviorMetrics...)
	if len(m.behaviorMetrics) > 512 {
		m.behaviorMetrics = m.behaviorMetrics[:512]
	}
	return nil
}

func (m *memoryStore) SaveBehaviorEvent(_ context.Context, event *model.BehaviorEvent) error {
	if event == nil {
		return errors.New("store: nil behavior event")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if event.ID == uuid.Nil {
		event.ID = uuid.New()
	}
	if event.CreatedAt.IsZero() {
		event.CreatedAt = time.Now()
	}
	copyEvent := *event
	if copyEvent.Metadata != nil {
		copyEvent.Metadata = copyMap(copyEvent.Metadata)
	}
	m.behaviorEvents = append([]model.BehaviorEvent{copyEvent}, m.behaviorEvents...)
	if len(m.behaviorEvents) > 512 {
		m.behaviorEvents = m.behaviorEvents[:512]
	}
	return nil
}

func (m *memoryStore) CreateAnomaly(_ context.Context, anomaly *model.Anomaly) error {
	if anomaly == nil {
		return errors.New("store: nil anomaly")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if anomaly.ID == uuid.Nil {
		anomaly.ID = uuid.New()
	}
	if anomaly.CreatedAt.IsZero() {
		anomaly.CreatedAt = time.Now()
	}
	if anomaly.UpdatedAt.IsZero() {
		anomaly.UpdatedAt = anomaly.CreatedAt
	}
	cp := *anomaly
	if anomaly.Summary != nil {
		cp.Summary = make(map[string]interface{}, len(anomaly.Summary))
		for k, v := range anomaly.Summary {
			cp.Summary[k] = v
		}
	}
	if len(anomaly.Entities) > 0 {
		cp.Entities = append([]string(nil), anomaly.Entities...)
	}
	m.anomalies[cp.ID] = &cp
	return nil
}

func (m *memoryStore) ListAnomalies(_ context.Context, limit int) ([]*model.Anomaly, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if limit <= 0 {
		limit = 50
	}
	list := make([]*model.Anomaly, 0, len(m.anomalies))
	for _, anomaly := range m.anomalies {
		cp := *anomaly
		if anomaly.Summary != nil {
			cp.Summary = make(map[string]interface{}, len(anomaly.Summary))
			for k, v := range anomaly.Summary {
				cp.Summary[k] = v
			}
		}
		if len(anomaly.Entities) > 0 {
			cp.Entities = append([]string(nil), anomaly.Entities...)
		}
		list = append(list, &cp)
	}
	sort.Slice(list, func(i, j int) bool {
		return list[i].CreatedAt.After(list[j].CreatedAt)
	})
	if len(list) > limit {
		list = list[:limit]
	}
	return list, nil
}

func (m *memoryStore) ListAnomaliesByFilter(_ context.Context, filter model.AnomalyFilter) ([]*model.Anomaly, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	limit := filter.Limit
	if limit <= 0 {
		limit = 50
	}
	var results []*model.Anomaly
	for _, anomaly := range m.anomalies {
		if filter.AgentID != nil && anomaly.AgentID != *filter.AgentID {
			continue
		}
		if filter.TaskID != nil && anomaly.TaskID != *filter.TaskID {
			continue
		}
		if filter.MinScore > 0 && anomaly.Score < filter.MinScore {
			continue
		}
		if len(filter.Status) > 0 && !containsString(filter.Status, anomaly.Status) {
			continue
		}
		if filter.IOC != "" && !matchIOC(filter.IOC, anomaly) {
			continue
		}
		cp := *anomaly
		if anomaly.Summary != nil {
			cp.Summary = make(map[string]interface{}, len(anomaly.Summary))
			for k, v := range anomaly.Summary {
				cp.Summary[k] = v
			}
		}
		if len(anomaly.Entities) > 0 {
			cp.Entities = append([]string(nil), anomaly.Entities...)
		}
		results = append(results, &cp)
	}
	sort.Slice(results, func(i, j int) bool {
		return results[i].CreatedAt.After(results[j].CreatedAt)
	})
	if len(results) > limit {
		results = results[:limit]
	}
	return results, nil
}

func (m *memoryStore) GetAnomaly(_ context.Context, id uuid.UUID) (*model.Anomaly, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	anomaly, ok := m.anomalies[id]
	if !ok {
		return nil, ErrNotFound
	}
	cp := *anomaly
	if anomaly.Summary != nil {
		cp.Summary = make(map[string]interface{}, len(anomaly.Summary))
		for k, v := range anomaly.Summary {
			cp.Summary[k] = v
		}
	}
	if len(anomaly.Entities) > 0 {
		cp.Entities = append([]string(nil), anomaly.Entities...)
	}
	return &cp, nil
}

func (m *memoryStore) SaveAnomalyGraph(_ context.Context, anomalyID uuid.UUID, nodes []*model.BehaviorGraphNode, edges []*model.BehaviorGraphEdge) error {
	if anomalyID == uuid.Nil {
		return errors.New("store: anomalyID required")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	graph := &model.AnomalyGraph{
		Nodes: make([]*model.BehaviorGraphNode, 0, len(nodes)),
		Edges: make([]*model.BehaviorGraphEdge, 0, len(edges)),
	}
	for _, node := range nodes {
		if node == nil {
			continue
		}
		cp := *node
		if node.Properties != nil {
			cp.Properties = make(map[string]interface{}, len(node.Properties))
			for k, v := range node.Properties {
				cp.Properties[k] = v
			}
		}
		graph.Nodes = append(graph.Nodes, &cp)
	}
	for _, edge := range edges {
		if edge == nil {
			continue
		}
		cp := *edge
		if edge.Properties != nil {
			cp.Properties = make(map[string]interface{}, len(edge.Properties))
			for k, v := range edge.Properties {
				cp.Properties[k] = v
			}
		}
		graph.Edges = append(graph.Edges, &cp)
	}
	m.behaviorGraphs[anomalyID] = graph
	return nil
}

func (m *memoryStore) GetAnomalyGraph(_ context.Context, anomalyID uuid.UUID) (*model.AnomalyGraph, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	graph, ok := m.behaviorGraphs[anomalyID]
	if !ok {
		return &model.AnomalyGraph{Nodes: nil, Edges: nil}, nil
	}
	result := &model.AnomalyGraph{
		Nodes: make([]*model.BehaviorGraphNode, 0, len(graph.Nodes)),
		Edges: make([]*model.BehaviorGraphEdge, 0, len(graph.Edges)),
	}
	for _, node := range graph.Nodes {
		cp := *node
		if node.Properties != nil {
			cp.Properties = make(map[string]interface{}, len(node.Properties))
			for k, v := range node.Properties {
				cp.Properties[k] = v
			}
		}
		result.Nodes = append(result.Nodes, &cp)
	}
	for _, edge := range graph.Edges {
		cp := *edge
		if edge.Properties != nil {
			cp.Properties = make(map[string]interface{}, len(edge.Properties))
			for k, v := range edge.Properties {
				cp.Properties[k] = v
			}
		}
		result.Edges = append(result.Edges, &cp)
	}
	return result, nil
}

func containsString(list []string, target string) bool {
	for _, val := range list {
		if strings.EqualFold(strings.TrimSpace(val), strings.TrimSpace(target)) {
			return true
		}
	}
	return false
}

func matchIOC(query string, anomaly *model.Anomaly) bool {
	if anomaly == nil {
		return false
	}
	q := strings.ToLower(strings.TrimSpace(query))
	if q == "" {
		return true
	}
	if anomaly.IOC != "" && strings.Contains(strings.ToLower(anomaly.IOC), q) {
		return true
	}
	for _, entity := range anomaly.Entities {
		if strings.Contains(strings.ToLower(entity), q) {
			return true
		}
	}
	if anomaly.Summary != nil {
		for key, val := range anomaly.Summary {
			if strings.Contains(strings.ToLower(key), q) {
				return true
			}
			if strings.Contains(strings.ToLower(fmt.Sprint(val)), q) {
				return true
			}
		}
	}
	return false
}

func (m *memoryStore) CreatePlaybook(_ context.Context, playbook *model.Playbook) error {
	if playbook == nil {
		return errors.New("store: nil playbook")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if playbook.ID == uuid.Nil {
		playbook.ID = uuid.New()
	}
	if playbook.CreatedAt.IsZero() {
		playbook.CreatedAt = time.Now()
	}
	playbook.UpdatedAt = time.Now()
	cp := *playbook
	if playbook.Conditions != nil {
		cp.Conditions = append([]string(nil), playbook.Conditions...)
	}
	if playbook.Actions != nil {
		cp.Actions = append([]model.PlaybookAction(nil), playbook.Actions...)
	}
	if playbook.Rollback != nil {
		cp.Rollback = append([]model.PlaybookAction(nil), playbook.Rollback...)
	}
	if playbook.Approvals != nil {
		cp.Approvals = append([]model.PlaybookApproval(nil), playbook.Approvals...)
	}
	if playbook.ApprovalStates != nil {
		cp.ApprovalStates = append([]model.PlaybookApprovalState(nil), playbook.ApprovalStates...)
	}
	m.playbooks[cp.ID] = &cp
	return nil
}

func (m *memoryStore) UpdatePlaybook(_ context.Context, playbook *model.Playbook) error {
	if playbook == nil || playbook.ID == uuid.Nil {
		return errors.New("store: invalid playbook")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	existing, ok := m.playbooks[playbook.ID]
	if !ok {
		return ErrNotFound
	}
	if playbook.Conditions != nil {
		playbook.Conditions = append([]string(nil), playbook.Conditions...)
	}
	if playbook.Actions != nil {
		playbook.Actions = append([]model.PlaybookAction(nil), playbook.Actions...)
	}
	if playbook.Rollback != nil {
		playbook.Rollback = append([]model.PlaybookAction(nil), playbook.Rollback...)
	}
	if playbook.Approvals != nil {
		playbook.Approvals = append([]model.PlaybookApproval(nil), playbook.Approvals...)
	}
	if playbook.ApprovalStates != nil {
		playbook.ApprovalStates = append([]model.PlaybookApprovalState(nil), playbook.ApprovalStates...)
	}
	playbook.UpdatedAt = time.Now()
	*existing = *playbook
	return nil
}

func (m *memoryStore) GetPlaybook(_ context.Context, id uuid.UUID) (*model.Playbook, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	playbook, ok := m.playbooks[id]
	if !ok {
		return nil, ErrNotFound
	}
	cp := *playbook
	if playbook.Conditions != nil {
		cp.Conditions = append([]string(nil), playbook.Conditions...)
	}
	if playbook.Actions != nil {
		cp.Actions = append([]model.PlaybookAction(nil), playbook.Actions...)
	}
	if playbook.Rollback != nil {
		cp.Rollback = append([]model.PlaybookAction(nil), playbook.Rollback...)
	}
	if playbook.Approvals != nil {
		cp.Approvals = append([]model.PlaybookApproval(nil), playbook.Approvals...)
	}
	if playbook.ApprovalStates != nil {
		cp.ApprovalStates = append([]model.PlaybookApprovalState(nil), playbook.ApprovalStates...)
	}
	return &cp, nil
}

func (m *memoryStore) ListPlaybooks(_ context.Context, limit int) ([]*model.Playbook, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if limit <= 0 {
		limit = 50
	}
	results := make([]*model.Playbook, 0, len(m.playbooks))
	for _, pb := range m.playbooks {
		cp := *pb
		if pb.Conditions != nil {
			cp.Conditions = append([]string(nil), pb.Conditions...)
		}
		if pb.Actions != nil {
			cp.Actions = append([]model.PlaybookAction(nil), pb.Actions...)
		}
		if pb.Rollback != nil {
			cp.Rollback = append([]model.PlaybookAction(nil), pb.Rollback...)
		}
		if pb.Approvals != nil {
			cp.Approvals = append([]model.PlaybookApproval(nil), pb.Approvals...)
		}
		if pb.ApprovalStates != nil {
			cp.ApprovalStates = append([]model.PlaybookApprovalState(nil), pb.ApprovalStates...)
		}
		results = append(results, &cp)
	}
	sort.Slice(results, func(i, j int) bool {
		return results[i].UpdatedAt.After(results[j].UpdatedAt)
	})
	if len(results) > limit {
		results = results[:limit]
	}
	return results, nil
}

func (m *memoryStore) CreatePlaybookRun(_ context.Context, run *model.PlaybookRun) error {
	if run == nil {
		return errors.New("store: nil playbook run")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if run.ID == uuid.Nil {
		run.ID = uuid.New()
	}
	if run.CreatedAt.IsZero() {
		run.CreatedAt = time.Now()
	}
	run.UpdatedAt = run.CreatedAt
	cp := *run
	if run.Steps != nil {
		cp.Steps = append([]model.PlaybookRunStep(nil), run.Steps...)
	}
	if run.Event != nil {
		cp.Event = cloneAnyMap(run.Event)
	}
	if run.Result != nil {
		cp.Result = cloneAnyMap(run.Result)
	}
	m.playbookRuns[cp.ID] = &cp
	return nil
}

func (m *memoryStore) UpdatePlaybookRun(_ context.Context, run *model.PlaybookRun) error {
	if run == nil || run.ID == uuid.Nil {
		return errors.New("store: invalid playbook run")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	existing, ok := m.playbookRuns[run.ID]
	if !ok {
		return ErrNotFound
	}
	run.UpdatedAt = time.Now()
	if run.Steps != nil {
		run.Steps = append([]model.PlaybookRunStep(nil), run.Steps...)
	}
	if run.Event != nil {
		run.Event = cloneAnyMap(run.Event)
	}
	if run.Result != nil {
		run.Result = cloneAnyMap(run.Result)
	}
	*existing = *run
	return nil
}

func (m *memoryStore) ListPlaybookRuns(_ context.Context, playbookID uuid.UUID, limit int) ([]*model.PlaybookRun, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if limit <= 0 {
		limit = 50
	}
	results := make([]*model.PlaybookRun, 0)
	for _, run := range m.playbookRuns {
		if run.PlaybookID != playbookID {
			continue
		}
		cp := *run
		if run.Steps != nil {
			cp.Steps = append([]model.PlaybookRunStep(nil), run.Steps...)
		}
		if run.Event != nil {
			cp.Event = cloneAnyMap(run.Event)
		}
		if run.Result != nil {
			cp.Result = cloneAnyMap(run.Result)
		}
		results = append(results, &cp)
	}
	sort.Slice(results, func(i, j int) bool {
		return results[i].CreatedAt.After(results[j].CreatedAt)
	})
	if len(results) > limit {
		results = results[:limit]
	}
	return results, nil
}

func (m *memoryStore) CreateBASScenario(_ context.Context, scenario *model.BASScenario) error {
	if scenario == nil {
		return fmt.Errorf("store: nil bas scenario")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if scenario.ID == uuid.Nil {
		scenario.ID = uuid.New()
	}
	m.basScenarios[scenario.ID] = cloneBASScenario(scenario)
	return nil
}

func (m *memoryStore) UpdateBASScenario(_ context.Context, scenario *model.BASScenario) error {
	if scenario == nil || scenario.ID == uuid.Nil {
		return fmt.Errorf("store: invalid bas scenario")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.basScenarios[scenario.ID]; !ok {
		return ErrNotFound
	}
	m.basScenarios[scenario.ID] = cloneBASScenario(scenario)
	return nil
}

func (m *memoryStore) GetBASScenario(_ context.Context, id uuid.UUID) (*model.BASScenario, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	scenario, ok := m.basScenarios[id]
	if !ok {
		return nil, ErrNotFound
	}
	return cloneBASScenario(scenario), nil
}

func (m *memoryStore) ListBASScenarios(_ context.Context) ([]*model.BASScenario, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	results := make([]*model.BASScenario, 0, len(m.basScenarios))
	for _, scenario := range m.basScenarios {
		results = append(results, cloneBASScenario(scenario))
	}
	return results, nil
}

func (m *memoryStore) DeleteBASScenario(_ context.Context, id uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.basScenarios[id]; !ok {
		return ErrNotFound
	}
	delete(m.basScenarios, id)
	return nil
}

func cloneAnyMap(src map[string]interface{}) map[string]interface{} {
	if src == nil {
		return nil
	}
	dst := make(map[string]interface{}, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

func (m *memoryStore) CreateComplianceFramework(_ context.Context, framework *model.ComplianceFramework) error {
	if framework == nil {
		return errors.New("store: nil framework")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if framework.ID == uuid.Nil {
		framework.ID = uuid.New()
	}
	now := time.Now()
	framework.CreatedAt = now
	framework.UpdatedAt = now
	cp := *framework
	m.frameworks[cp.ID] = &cp
	return nil
}

func (m *memoryStore) UpdateComplianceFramework(_ context.Context, framework *model.ComplianceFramework) error {
	if framework == nil || framework.ID == uuid.Nil {
		return errors.New("store: invalid framework")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	existing, ok := m.frameworks[framework.ID]
	if !ok {
		return ErrNotFound
	}
	framework.UpdatedAt = time.Now()
	*existing = *framework
	return nil
}

func (m *memoryStore) ListComplianceFrameworks(_ context.Context) ([]*model.ComplianceFramework, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	items := make([]*model.ComplianceFramework, 0, len(m.frameworks))
	for _, fw := range m.frameworks {
		cp := *fw
		items = append(items, &cp)
	}
	sort.Slice(items, func(i, j int) bool {
		return items[i].Title < items[j].Title
	})
	return items, nil
}

func (m *memoryStore) CreateComplianceControl(_ context.Context, control *model.ComplianceControl) error {
	if control == nil {
		return errors.New("store: nil control")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if control.ID == uuid.Nil {
		control.ID = uuid.New()
	}
	control.CreatedAt = time.Now()
	control.UpdatedAt = control.CreatedAt
	cp := *control
	if control.References != nil {
		cp.References = make(map[string]string, len(control.References))
		for k, v := range control.References {
			cp.References[k] = v
		}
	}
	m.controls[cp.ID] = &cp
	return nil
}

func (m *memoryStore) UpdateComplianceControl(_ context.Context, control *model.ComplianceControl) error {
	if control == nil || control.ID == uuid.Nil {
		return errors.New("store: invalid control")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	existing, ok := m.controls[control.ID]
	if !ok {
		return ErrNotFound
	}
	if control.References != nil {
		control.References = copyMap(control.References)
	}
	control.UpdatedAt = time.Now()
	*existing = *control
	return nil
}

func (m *memoryStore) ListComplianceControls(_ context.Context, frameworkID uuid.UUID) ([]*model.ComplianceControl, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	items := make([]*model.ComplianceControl, 0)
	for _, ctrl := range m.controls {
		if ctrl.FrameworkID != frameworkID {
			continue
		}
		cp := *ctrl
		if ctrl.References != nil {
			cp.References = copyMap(ctrl.References)
		}
		items = append(items, &cp)
	}
	sort.Slice(items, func(i, j int) bool {
		return items[i].Code < items[j].Code
	})
	return items, nil
}

func (m *memoryStore) CreateControlMapping(_ context.Context, mapping *model.ControlMapping) error {
	if mapping == nil {
		return errors.New("store: nil control mapping")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if mapping.ID == uuid.Nil {
		mapping.ID = uuid.New()
	}
	if mapping.CreatedAt.IsZero() {
		mapping.CreatedAt = time.Now()
	}
	m.mappings[mapping.ControlID] = append(m.mappings[mapping.ControlID], *mapping)
	return nil
}

func (m *memoryStore) ListControlMappings(_ context.Context, controlID uuid.UUID) ([]*model.ControlMapping, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	rows := m.mappings[controlID]
	result := make([]*model.ControlMapping, 0, len(rows))
	for _, mapping := range rows {
		cp := mapping
		if mapping.Metadata != nil {
			cp.Metadata = copyMap(mapping.Metadata)
		}
		result = append(result, &cp)
	}
	return result, nil
}

func (m *memoryStore) CreateComplianceFinding(_ context.Context, finding *model.ComplianceFinding) error {
	if finding == nil {
		return errors.New("store: nil finding")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if finding.ID == uuid.Nil {
		finding.ID = uuid.New()
	}
	now := time.Now()
	if finding.CreatedAt.IsZero() {
		finding.CreatedAt = now
	}
	finding.UpdatedAt = finding.CreatedAt
	cp := *finding
	if finding.Evidence != nil {
		cp.Evidence = copyMap(finding.Evidence)
	}
	if finding.RemediationLogs != nil {
		cp.RemediationLogs = append([]model.RemediationNote(nil), finding.RemediationLogs...)
	}
	m.findings[cp.ID] = &cp
	return nil
}

func (m *memoryStore) UpdateComplianceFinding(_ context.Context, finding *model.ComplianceFinding) error {
	if finding == nil || finding.ID == uuid.Nil {
		return errors.New("store: invalid finding")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	existing, ok := m.findings[finding.ID]
	if !ok {
		return ErrNotFound
	}
	if finding.Evidence != nil {
		finding.Evidence = copyMap(finding.Evidence)
	}
	if finding.RemediationLogs != nil {
		finding.RemediationLogs = append([]model.RemediationNote(nil), finding.RemediationLogs...)
	}
	finding.UpdatedAt = time.Now()
	*existing = *finding
	return nil
}

func (m *memoryStore) GetComplianceFinding(_ context.Context, id uuid.UUID) (*model.ComplianceFinding, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	finding, ok := m.findings[id]
	if !ok {
		return nil, ErrNotFound
	}
	cp := *finding
	if finding.Evidence != nil {
		cp.Evidence = copyMap(finding.Evidence)
	}
	if finding.RemediationLogs != nil {
		cp.RemediationLogs = append([]model.RemediationNote(nil), finding.RemediationLogs...)
	}
	return &cp, nil
}

func (m *memoryStore) ListComplianceFindings(_ context.Context, frameworkID uuid.UUID, status string) ([]*model.ComplianceFinding, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var result []*model.ComplianceFinding
	for _, finding := range m.findings {
		if frameworkID != uuid.Nil && finding.FrameworkID != frameworkID {
			continue
		}
		if status != "" && !strings.EqualFold(finding.Status, status) {
			continue
		}
		cp := *finding
		if finding.Evidence != nil {
			cp.Evidence = copyMap(finding.Evidence)
		}
		if finding.RemediationLogs != nil {
			cp.RemediationLogs = append([]model.RemediationNote(nil), finding.RemediationLogs...)
		}
		result = append(result, &cp)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].UpdatedAt.After(result[j].UpdatedAt)
	})
	return result, nil
}

func (m *memoryStore) CreateThreatIntelSample(_ context.Context, sample *model.ThreatIntelSample) error {
	if sample == nil {
		return errors.New("store: nil threat intel sample")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if sample.ID == uuid.Nil {
		sample.ID = uuid.New()
	}
	now := time.Now()
	if sample.CreatedAt.IsZero() {
		sample.CreatedAt = now
	}
	sample.UpdatedAt = now
	cp := copyTISample(sample)
	m.tiSamples[cp.ID] = &cp
	return nil
}

func (m *memoryStore) UpdateThreatIntelSampleStatus(_ context.Context, sampleID uuid.UUID, status, lastError string, metadata map[string]string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	sample, ok := m.tiSamples[sampleID]
	if !ok {
		return ErrNotFound
	}
	if strings.TrimSpace(status) != "" {
		sample.Status = status
	}
	sample.LastError = lastError
	if metadata != nil {
		sample.Metadata = copyMap(metadata)
	}
	sample.UpdatedAt = time.Now()
	return nil
}

func (m *memoryStore) GetThreatIntelSample(_ context.Context, sampleID uuid.UUID) (*model.ThreatIntelSample, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	sample, ok := m.tiSamples[sampleID]
	if !ok {
		return nil, ErrNotFound
	}
	cp := copyTISample(sample)
	return &cp, nil
}

func (m *memoryStore) ListThreatIntelJobsBySample(_ context.Context, sampleID uuid.UUID) ([]*model.ThreatIntelJob, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	results := make([]*model.ThreatIntelJob, 0)
	for _, job := range m.tiJobs {
		if job.SampleID != sampleID {
			continue
		}
		cp := copyTIJob(job)
		results = append(results, &cp)
	}
	sort.Slice(results, func(i, j int) bool {
		if results[i].CreatedAt.Equal(results[j].CreatedAt) {
			return results[i].ID.String() < results[j].ID.String()
		}
		return results[i].CreatedAt.Before(results[j].CreatedAt)
	})
	return results, nil
}

func (m *memoryStore) InsertThreatIntelJob(_ context.Context, job *model.ThreatIntelJob) error {
	if job == nil {
		return errors.New("store: nil threat intel job")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if job.ID == uuid.Nil {
		job.ID = uuid.New()
	}
	now := time.Now()
	if job.CreatedAt.IsZero() {
		job.CreatedAt = now
	}
	job.UpdatedAt = now
	if job.Status == "" {
		job.Status = model.ThreatIntelJobStatusPending
	}
	cp := copyTIJob(job)
	m.tiJobs[cp.ID] = &cp
	return nil
}

func (m *memoryStore) LeaseThreatIntelJobs(_ context.Context, limit int) ([]*model.ThreatIntelJob, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if limit <= 0 {
		limit = 10
	}
	now := time.Now()
	results := make([]*model.ThreatIntelJob, 0, limit)
	for _, job := range m.tiJobs {
		if len(results) >= limit {
			break
		}
		if job.Status != model.ThreatIntelJobStatusPending && job.Status != model.ThreatIntelJobStatusRetryBackoff {
			continue
		}
		if !job.NextRunAt.IsZero() && job.NextRunAt.After(now) {
			continue
		}
		job.Status = model.ThreatIntelJobStatusRunning
		job.Attempt++
		job.UpdatedAt = now
		cp := copyTIJob(job)
		results = append(results, &cp)
	}
	return results, nil
}

func (m *memoryStore) UpdateThreatIntelJobStatus(_ context.Context, jobID uuid.UUID, status string, nextRunAt time.Time, errMsg string, metadata map[string]string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	job, ok := m.tiJobs[jobID]
	if !ok {
		return ErrNotFound
	}
	if strings.TrimSpace(status) != "" {
		job.Status = status
	}
	job.ErrorMsg = errMsg
	if !nextRunAt.IsZero() {
		job.NextRunAt = nextRunAt
	} else {
		job.NextRunAt = time.Time{}
	}
	if metadata != nil {
		job.Metadata = copyMap(metadata)
	}
	job.UpdatedAt = time.Now()
	return nil
}

func (m *memoryStore) InsertThreatIntelVerdict(_ context.Context, verdict *model.ThreatIntelVerdict) error {
	if verdict == nil {
		return errors.New("store: nil threat intel verdict")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if verdict.ID == uuid.Nil {
		verdict.ID = uuid.New()
	}
	if verdict.CreatedAt.IsZero() {
		verdict.CreatedAt = time.Now()
	}
	if verdict.ExpiresAt.IsZero() {
		verdict.ExpiresAt = verdict.RetrievedAt
	}
	cp := copyTIVerdict(verdict)
	m.tiVerdicts[cp.ID] = &cp
	return nil
}

func (m *memoryStore) ListThreatIntelVerdicts(_ context.Context, indicator string, limit int) ([]*model.ThreatIntelVerdict, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	indicator = strings.ToLower(strings.TrimSpace(indicator))
	results := make([]*model.ThreatIntelVerdict, 0)
	now := time.Now()
	for _, verdict := range m.tiVerdicts {
		if indicator != "" && strings.ToLower(verdict.Indicator) != indicator {
			continue
		}
		if !verdict.ExpiresAt.IsZero() && verdict.ExpiresAt.Before(now) {
			continue
		}
		cp := copyTIVerdict(verdict)
		results = append(results, &cp)
	}
	sort.Slice(results, func(i, j int) bool {
		if results[i].RetrievedAt.Equal(results[j].RetrievedAt) {
			return results[i].ID.String() > results[j].ID.String()
		}
		return results[i].RetrievedAt.After(results[j].RetrievedAt)
	})
	if limit > 0 && len(results) > limit {
		results = results[:limit]
	}
	return results, nil
}

func (m *memoryStore) CountThreatIntelJobs(_ context.Context, statuses []string) (int64, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if len(statuses) == 0 {
		return int64(len(m.tiJobs)), nil
	}
	allowed := make(map[string]struct{}, len(statuses))
	for _, st := range statuses {
		allowed[strings.ToLower(strings.TrimSpace(st))] = struct{}{}
	}
	var count int64
	for _, job := range m.tiJobs {
		if _, ok := allowed[strings.ToLower(job.Status)]; ok {
			count++
		}
	}
	return count, nil
}

func copyTISample(src *model.ThreatIntelSample) model.ThreatIntelSample {
	cp := *src
	if src.Metadata != nil {
		cp.Metadata = copyMap(src.Metadata)
	}
	cp.ArtifactIDs = copyUUIDs(src.ArtifactIDs)
	return cp
}

func copyTIJob(src *model.ThreatIntelJob) model.ThreatIntelJob {
	cp := *src
	if src.Metadata != nil {
		cp.Metadata = copyMap(src.Metadata)
	}
	cp.ArtifactIDs = copyUUIDs(src.ArtifactIDs)
	if src.Payload != nil {
		cp.Payload = append([]byte(nil), src.Payload...)
	}
	return cp
}

func copyTIVerdict(src *model.ThreatIntelVerdict) model.ThreatIntelVerdict {
	cp := *src
	if src.Metadata != nil {
		cp.Metadata = copyMap(src.Metadata)
	}
	if src.Raw != nil {
		cp.Raw = append([]byte(nil), src.Raw...)
	}
	return cp
}

func cloneBASScenario(src *model.BASScenario) *model.BASScenario {
	if src == nil {
		return nil
	}
	cp := *src
	if src.Tags != nil {
		cp.Tags = append([]string(nil), src.Tags...)
	}
	if src.NetworkBoundaries != nil {
		cp.NetworkBoundaries = append([]string(nil), src.NetworkBoundaries...)
	}
	if src.RequiredLabels != nil {
		cp.RequiredLabels = append([]string(nil), src.RequiredLabels...)
	}
	if src.Dependencies != nil {
		cp.Dependencies = append([]uuid.UUID(nil), src.Dependencies...)
	}
	if src.Steps != nil {
		cp.Steps = make([]model.BASScenarioStep, len(src.Steps))
		for idx, step := range src.Steps {
			cp.Steps[idx] = step
			if step.Args != nil {
				cp.Steps[idx].Args = cloneAnyMap(step.Args)
			}
			if step.Capabilities != nil {
				cp.Steps[idx].Capabilities = append([]string(nil), step.Capabilities...)
			}
			if step.DependsOn != nil {
				cp.Steps[idx].DependsOn = append([]string(nil), step.DependsOn...)
			}
			if step.TelemetryHints != nil {
				cp.Steps[idx].TelemetryHints = copyMap(step.TelemetryHints)
			}
			if step.ExecutionContext != nil {
				cp.Steps[idx].ExecutionContext = cloneAnyMap(step.ExecutionContext)
			}
		}
	}
	if src.ApprovalPolicy != nil {
		cp.ApprovalPolicy = append([]model.BASApprovalRule(nil), src.ApprovalPolicy...)
	}
	if src.ApprovalRecords != nil {
		cp.ApprovalRecords = append([]model.BASScenarioApprovalRecord(nil), src.ApprovalRecords...)
	}
	return &cp
}

func copyUUIDs(src []uuid.UUID) []uuid.UUID {
	if len(src) == 0 {
		return nil
	}
	dst := make([]uuid.UUID, len(src))
	copy(dst, src)
	return dst
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
