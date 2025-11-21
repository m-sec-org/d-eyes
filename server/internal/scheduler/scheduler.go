package scheduler

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/m-sec-org/d-eyes/server/internal/alerts"
	"github.com/m-sec-org/d-eyes/server/internal/audit"
	"github.com/m-sec-org/d-eyes/server/internal/config"
	"github.com/m-sec-org/d-eyes/server/internal/metrics"
	"github.com/m-sec-org/d-eyes/server/internal/model"
	"github.com/m-sec-org/d-eyes/server/internal/queue"
	"github.com/m-sec-org/d-eyes/server/internal/store"
	"github.com/m-sec-org/d-eyes/server/internal/streams"
)

var (
	ErrNoTaskAvailable = errors.New("scheduler: no task available")
	ErrAgentAtCapacity = errors.New("scheduler: agent at capacity")
)

const maxTaskEligibilityScan = 64

// Scheduler manages task leasing and dispatching.
type Scheduler struct {
	store store.Store
	queue queue.Queue
	cfg   config.SchedulerConfig
	m     *metrics.Metrics

	mu            sync.Mutex
	totalInFlight int
	agentInFlight map[uuid.UUID]int
	statusCounts  map[model.TaskStatus]int64
	resultWriter  resultWriter
	basInFlight   int
	basPending    int64
	auditRecorder audit.Recorder
	alertNotifier alerts.Notifier
	taskHub       *streams.Hub
}

type resultWriter interface {
	InsertTaskResult(ctx context.Context, result *model.TaskResult) error
}

func New(store store.Store, queue queue.Queue, cfg config.SchedulerConfig) *Scheduler {
	return &Scheduler{
		store:         store,
		queue:         queue,
		cfg:           cfg,
		agentInFlight: make(map[uuid.UUID]int),
		statusCounts:  make(map[model.TaskStatus]int64),
		resultWriter:  store,
	}
}

// SetMetrics wires Prometheus collectors into the scheduler.
func (s *Scheduler) SetMetrics(m *metrics.Metrics) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m = m
	if s.m != nil {
		s.m.TasksInFlight.Set(float64(s.totalInFlight))
		for status, count := range s.statusCounts {
			s.m.TaskStatus.WithLabelValues(string(status)).Set(float64(count))
		}
	}
}

// SetAudit wires审计事件记录器。
func (s *Scheduler) SetAudit(recorder audit.Recorder) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.auditRecorder = recorder
}

// SetAlerts 配置 BAS 告警通知器。
func (s *Scheduler) SetAlerts(notifier alerts.Notifier) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.alertNotifier = notifier
}

// SetTaskHub 注册任务事件 hub。
func (s *Scheduler) SetTaskHub(hub *streams.Hub) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.taskHub = hub
}

// RecordNewTask updates internal counters for freshly created tasks.
func (s *Scheduler) RecordNewTask(status model.TaskStatus) {
	s.observeStatusChange("", status)
	s.publishStats()
}

// LeaseTask assigns a task to an agent, creating a TaskRun with lease TTL.
func (s *Scheduler) LeaseTask(ctx context.Context, agent *model.Agent) (task *model.Task, run *model.TaskRun, err error) {
	if !s.reserveCapacity(agent.ID) {
		return nil, nil, ErrAgentAtCapacity
	}
	defer func() {
		if err != nil {
			s.releaseCapacity(agent.ID)
		}
	}()

	skippedTasks := make(map[uuid.UUID]struct{})
	for {
		task, err = s.dequeueTask(ctx, agent.Capabilities)
		if err != nil {
			return nil, nil, err
		}
		if task == nil {
			return nil, nil, ErrNoTaskAvailable
		}
		if _, seen := skippedTasks[task.ID]; seen {
			if err := s.requeueTask(ctx, task); err != nil {
				return nil, nil, err
			}
			return nil, nil, ErrNoTaskAvailable
		}
		if eligible, _ := s.agentEligibleForTask(agent, task); eligible {
			break
		}
		skippedTasks[task.ID] = struct{}{}
		if err := s.requeueTask(ctx, task); err != nil {
			return nil, nil, err
		}
		task = nil
		if len(skippedTasks) >= maxTaskEligibilityScan {
			return nil, nil, ErrNoTaskAvailable
		}
	}

	if !s.reserveBAS(task.Type) {
		_ = s.requeueTask(ctx, task)
		s.releaseCapacity(agent.ID)
		if s.m != nil {
			s.observeQueueDepth(ctx)
		}
		return nil, nil, ErrNoTaskAvailable
	}
	defer func() {
		if err != nil {
			s.releaseBAS(task.Type)
		}
	}()

	leaseID := uuid.New()
	run = &model.TaskRun{
		ID:            uuid.New(),
		TaskID:        task.ID,
		TaskType:      task.Type,
		AgentID:       agent.ID,
		LeaseID:       leaseID,
		LeaseExpires:  time.Now().Add(s.cfg.LeaseTTL),
		Status:        model.TaskStatusLeased,
		RetrySequence: task.RetryCount,
	}

	if err = s.store.CreateTaskRun(ctx, run); err != nil {
		_ = s.requeueTask(ctx, task)
		return nil, nil, err
	}

	prevStatus := task.Status
	if err = s.store.UpdateTaskStatus(ctx, task.ID, model.TaskStatusLeased); err != nil {
		_ = s.requeueTask(ctx, task)
		return nil, nil, err
	}

	s.observeStatusChange(prevStatus, model.TaskStatusLeased)
	s.observeQueueDepth(ctx)
	s.publishTaskEvent(streams.TaskEvent{
		Event:    "leased",
		TaskID:   task.ID.String(),
		TaskType: string(task.Type),
		Status:   string(model.TaskStatusLeased),
		AgentID:  agent.ID.String(),
	})
	s.publishStats()

	if s.m != nil && !task.CreatedAt.IsZero() {
		wait := time.Since(task.CreatedAt)
		if wait >= 0 {
			s.m.TaskTimeToLease.Observe(wait.Seconds())
		}
	}
	return task, run, nil
}

// ReleaseAgentCapacity can be used by callers to explicitly free reserved slots when a lease fails to start.
func (s *Scheduler) ReleaseAgentCapacity(agentID uuid.UUID) {
	s.releaseCapacity(agentID)
}

// HandleLeaseTimeout processes leases that have expired without completion.
func (s *Scheduler) HandleLeaseTimeout(ctx context.Context, run *model.TaskRun) error {
	if run == nil {
		return errors.New("scheduler: nil task run")
	}
	if time.Now().Before(run.LeaseExpires) {
		return nil
	}

	s.releaseCapacity(run.AgentID)
	s.releaseBAS(run.TaskType)

	var metadata map[string]string
	if run.Metadata != nil {
		metadata = make(map[string]string, len(run.Metadata))
		for k, v := range run.Metadata {
			metadata[k] = v
		}
	}
	if metadata == nil {
		metadata = make(map[string]string)
	}
	metadata["error"] = "lease_timeout"

	if err := s.store.UpdateTaskRunCompletion(ctx, run.ID, model.TaskStatusFailed, time.Now(), nil, "lease expired", metadata, 1, "lease_timeout", time.Time{}); err != nil {
		return err
	}

	s.observeStatusChange(run.Status, model.TaskStatusFailed)
	if s.m != nil {
		s.m.TasksCompleted.WithLabelValues(string(model.TaskStatusFailed)).Inc()
	}

	task, err := s.store.GetTask(ctx, run.TaskID)
	if err != nil {
		return err
	}

	if err := s.store.IncrementTaskRetry(ctx, run.TaskID); err != nil {
		return err
	}
	task.RetryCount++

	if s.cfg.MaxRetries > 0 && task.RetryCount > s.cfg.MaxRetries {
		prevStatus := task.Status
		if err := s.store.UpdateTaskStatus(ctx, task.ID, model.TaskStatusFailed); err != nil {
			return err
		}
		s.observeStatusChange(prevStatus, model.TaskStatusFailed)
		s.publishTaskEvent(streams.TaskEvent{
			Event:    "timeout_exhausted",
			TaskID:   task.ID.String(),
			TaskType: string(task.Type),
			Status:   string(model.TaskStatusFailed),
		})
		s.publishStats()
		return nil
	}

	prevStatus := task.Status
	if err := s.store.UpdateTaskStatus(ctx, task.ID, model.TaskStatusPending); err != nil {
		return err
	}
	task.Status = model.TaskStatusPending
	s.observeStatusChange(prevStatus, model.TaskStatusPending)

	if err := s.requeueTask(ctx, task); err != nil {
		return err
	}
	s.observeQueueDepth(ctx)
	s.publishTaskEvent(streams.TaskEvent{
		Event:    "timeout_requeued",
		TaskID:   task.ID.String(),
		TaskType: string(task.Type),
		Status:   string(model.TaskStatusPending),
	})
	s.publishStats()
	return nil
}

// CompleteTask finalises a task run, updating status and metrics.
func (s *Scheduler) CompleteTask(ctx context.Context, run *model.TaskRun, status model.TaskStatus, summary []byte, errMsg string, metadata map[string]string, exitCode int32, errorCode string, artifacts []model.Artifact) error {
	if run == nil {
		return errors.New("scheduler: nil task run")
	}

	now := time.Now()
	var expiresAt time.Time
	if s.cfg.ResultRetention > 0 {
		expiresAt = now.Add(s.cfg.ResultRetention)
	}
	if err := s.store.UpdateTaskRunCompletion(ctx, run.ID, status, now, summary, errMsg, metadata, exitCode, errorCode, expiresAt); err != nil {
		return err
	}

	if err := s.store.UpdateTaskStatus(ctx, run.TaskID, status); err != nil {
		return err
	}

	if len(artifacts) > 0 {
		if err := s.store.SaveArtifacts(ctx, artifacts); err != nil {
			return err
		}
	}

	if s.resultWriter != nil {
		task, err := s.store.GetTask(ctx, run.TaskID)
		if err == nil {
			scenarioID := metadata["scenario_id"]
			scenarioName := metadata["scenario_name"]
			result := &model.TaskResult{
				TaskID:       task.ID,
				TaskType:     task.Type,
				Profile:      task.Profile,
				RunID:        run.ID,
				AgentID:      run.AgentID,
				Status:       status,
				Metadata:     metadata,
				Summary:      summary,
				ErrorMessage: errMsg,
				ExitCode:     exitCode,
				ErrorCode:    errorCode,
				ScenarioID:   scenarioID,
				ScenarioName: scenarioName,
				CompletedAt:  now,
				CreatedAt:    now,
			}
			_ = s.resultWriter.InsertTaskResult(ctx, result)
		}
	}

	s.releaseCapacity(run.AgentID)
	s.releaseBAS(run.TaskType)
	s.observeStatusChange(run.Status, status)

	if s.m != nil {
		s.m.TasksCompleted.WithLabelValues(string(status)).Inc()
		if run.StartedAt != nil && !run.StartedAt.IsZero() {
			s.m.TaskRunDuration.Observe(time.Since(*run.StartedAt).Seconds())
		}
	}

	if run.TaskType == model.TaskType("bas") {
		s.observeBASMetrics(metadata, status)
		execSummary := extractBASExecution(summary)
		s.recordBASAudit(run, metadata, execSummary, status, errMsg, exitCode)
		s.notifyBASAlerts(run, metadata, execSummary, status, errMsg, exitCode)
	}

	s.publishTaskEvent(streams.TaskEvent{
		Event:        "completed",
		TaskID:       run.TaskID.String(),
		TaskType:     string(run.TaskType),
		Status:       string(status),
		AgentID:      run.AgentID.String(),
		ScenarioID:   metadataValue(metadata, "scenario_id", ""),
		ScenarioName: metadataValue(metadata, "scenario_name", ""),
		Metadata:     metadata,
	})
	s.publishStats()
	return nil
}

// MarkRunStarted transitions a leased run to running.
func (s *Scheduler) MarkRunStarted(ctx context.Context, leaseID uuid.UUID) (err error) {
	run, err := s.store.GetTaskRunByLease(ctx, leaseID)
	if err != nil {
		return err
	}
	agentID := run.AgentID
	defer func() {
		if err != nil {
			s.releaseCapacity(agentID)
			if run != nil {
				s.releaseBAS(run.TaskType)
			}
		}
	}()

	if err = s.store.UpdateTaskRunStatusByLease(ctx, leaseID, model.TaskStatusRunning); err != nil {
		return err
	}
	if err = s.store.UpdateTaskStatus(ctx, run.TaskID, model.TaskStatusRunning); err != nil {
		return err
	}
	s.observeStatusChange(run.Status, model.TaskStatusRunning)
	s.publishTaskEvent(streams.TaskEvent{
		Event:    "running",
		TaskID:   run.TaskID.String(),
		TaskType: string(run.TaskType),
		Status:   string(model.TaskStatusRunning),
		AgentID:  run.AgentID.String(),
	})
	s.publishStats()
	return nil
}

func (s *Scheduler) observeBASMetrics(metadata map[string]string, status model.TaskStatus) {
	if s.m == nil {
		return
	}
	scenarioID := metadataValue(metadata, "scenario_id", "unknown")
	sandboxUsed := "false"
	if metadataBool(metadata, "sandbox_executed") {
		sandboxUsed = "true"
	}
	s.m.BASRuns.WithLabelValues(scenarioID, string(status), sandboxUsed).Inc()

	if metadataBool(metadata, "sandbox_fallback") {
		s.m.BASSandboxFallbacks.WithLabelValues(scenarioID).Inc()
	}
	if metadataBool(metadata, "sandbox_approval_required") {
		approved := "false"
		if metadataBool(metadata, "sandbox_approved") {
			approved = "true"
		}
		s.m.BASApprovals.WithLabelValues(approved).Inc()
	}
}

func (s *Scheduler) recordBASAudit(run *model.TaskRun, metadata map[string]string, exec basExecution, status model.TaskStatus, errMsg string, exitCode int32) {
	if s.auditRecorder == nil {
		return
	}
	event := audit.Event{
		TaskID:           run.TaskID.String(),
		RunID:            run.ID.String(),
		AgentID:          run.AgentID.String(),
		ScenarioID:       metadataValue(metadata, "scenario_id", ""),
		ScenarioName:     metadataValue(metadata, "scenario_name", ""),
		Status:           string(status),
		ExitCode:         exitCode,
		ErrorMessage:     chooseErrorMessage(exec.ErrorMessage, errMsg, metadataValue(metadata, "error_message", "")),
		SandboxEnabled:   metadataBool(metadata, "sandbox_enabled"),
		SandboxUsed:      metadataBool(metadata, "sandbox_executed"),
		SandboxFallback:  metadataBool(metadata, "sandbox_fallback"),
		ApprovalRequired: metadataBool(metadata, "sandbox_approval_required"),
		ApprovalGranted:  metadataBool(metadata, "sandbox_approved"),
		Metadata:         metadata,
		Notes:            exec.Notes,
		Risks:            exec.Risks,
	}
	_ = s.auditRecorder.Record(event)
}

func (s *Scheduler) notifyBASAlerts(run *model.TaskRun, metadata map[string]string, exec basExecution, status model.TaskStatus, errMsg string, exitCode int32) {
	if s.alertNotifier == nil {
		return
	}
	event := alerts.Event{
		TaskID:           run.TaskID.String(),
		RunID:            run.ID.String(),
		ScenarioID:       metadataValue(metadata, "scenario_id", ""),
		ScenarioName:     metadataValue(metadata, "scenario_name", ""),
		Status:           string(status),
		ErrorMessage:     chooseErrorMessage(exec.ErrorMessage, errMsg, metadataValue(metadata, "error_message", "")),
		SandboxFallback:  metadataBool(metadata, "sandbox_fallback"),
		SandboxUsed:      metadataBool(metadata, "sandbox_executed"),
		ApprovalRequired: metadataBool(metadata, "sandbox_approval_required"),
		ApprovalGranted:  metadataBool(metadata, "sandbox_approved"),
		Timestamp:        time.Now().UTC(),
	}
	s.alertNotifier.NotifyBAS(event)
}

type basExecution struct {
	Notes        []string
	Risks        map[string]int
	ErrorMessage string
}

func extractBASExecution(summary []byte) basExecution {
	if len(summary) == 0 {
		return basExecution{}
	}
	var payload struct {
		Summary struct {
			Notes        []string       `json:"notes"`
			Risks        map[string]int `json:"risks"`
			ErrorMessage string         `json:"error_message"`
		} `json:"summary"`
	}
	if err := json.Unmarshal(summary, &payload); err != nil {
		return basExecution{}
	}
	return basExecution{
		Notes:        payload.Summary.Notes,
		Risks:        payload.Summary.Risks,
		ErrorMessage: payload.Summary.ErrorMessage,
	}
}

func metadataValue(metadata map[string]string, key, fallback string) string {
	if metadata == nil {
		return fallback
	}
	if v, ok := metadata[key]; ok && strings.TrimSpace(v) != "" {
		return v
	}
	return fallback
}

func metadataBool(metadata map[string]string, key string) bool {
	val := metadataValue(metadata, key, "")
	if val == "" {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(val)) {
	case "true", "1", "yes", "y", "on":
		return true
	default:
		return false
	}
}

func (s *Scheduler) agentEligibleForTask(agent *model.Agent, task *model.Task) (bool, string) {
	if agent == nil || task == nil {
		return false, "invalid agent or task"
	}
	if task.Type != model.TaskType("bas") {
		return true, ""
	}
	metadata := task.Metadata
	if metadata == nil {
		return true, ""
	}
	if boundaries := splitCSV(metadataValue(metadata, "network_boundaries", "")); len(boundaries) > 0 {
		if !agentMatchesBoundaries(agent, boundaries) {
			return false, "network boundary mismatch"
		}
	}
	if required := splitCSV(metadataValue(metadata, "scenario_required_labels", "")); len(required) > 0 {
		if !agentMatchesLabelRequirements(agent, required) {
			return false, "required labels missing"
		}
	}
	return true, ""
}

func agentMatchesBoundaries(agent *model.Agent, boundaries []string) bool {
	if len(boundaries) == 0 {
		return true
	}
	agentValues := agentBoundaryValues(agent)
	if len(agentValues) == 0 {
		return false
	}
	allowed := make(map[string]struct{}, len(boundaries))
	for _, boundary := range boundaries {
		value := strings.ToLower(strings.TrimSpace(boundary))
		switch value {
		case "", "any", "all", "*":
			return true
		}
		allowed[value] = struct{}{}
	}
	for _, candidate := range agentValues {
		if _, ok := allowed[strings.ToLower(candidate)]; ok {
			return true
		}
	}
	return false
}

func agentBoundaryValues(agent *model.Agent) []string {
	if agent == nil || len(agent.Labels) == 0 {
		return nil
	}
	keys := []string{"network_boundary", "network.boundary", "network_boundaries", "zone"}
	values := make([]string, 0, len(keys))
	for _, key := range keys {
		if raw, ok := agent.Labels[key]; ok {
			values = append(values, splitCSV(raw)...)
		}
	}
	return values
}

func agentMatchesLabelRequirements(agent *model.Agent, raw []string) bool {
	reqs := parseLabelRequirements(raw)
	if len(reqs) == 0 {
		return true
	}
	labels := normaliseLabels(agent)
	for _, req := range reqs {
		actual, ok := labels[req.key]
		if !ok {
			return false
		}
		if req.value == "" {
			continue
		}
		if !labelValueMatches(actual, req.value) {
			return false
		}
	}
	return true
}

type labelRequirement struct {
	key   string
	value string
}

func parseLabelRequirements(values []string) []labelRequirement {
	result := make([]labelRequirement, 0, len(values))
	for _, raw := range values {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			continue
		}
		key := trimmed
		val := ""
		if idx := strings.IndexAny(trimmed, "=:"); idx >= 0 {
			key = trimmed[:idx]
			val = trimmed[idx+1:]
		}
		key = strings.ToLower(strings.TrimSpace(key))
		val = strings.ToLower(strings.TrimSpace(val))
		if key == "" {
			continue
		}
		result = append(result, labelRequirement{key: key, value: val})
	}
	return result
}

func normaliseLabels(agent *model.Agent) map[string]string {
	result := make(map[string]string)
	if agent == nil || len(agent.Labels) == 0 {
		return result
	}
	for k, v := range agent.Labels {
		key := strings.ToLower(strings.TrimSpace(k))
		if key == "" {
			continue
		}
		result[key] = strings.ToLower(strings.TrimSpace(v))
	}
	return result
}

func labelValueMatches(actual, expected string) bool {
	if expected == "" {
		return true
	}
	for _, candidate := range splitCSV(actual) {
		if strings.EqualFold(candidate, expected) {
			return true
		}
	}
	return false
}

func splitCSV(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parts := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ';'
	})
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			result = append(result, part)
		}
	}
	return result
}

func chooseErrorMessage(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func (s *Scheduler) publishTaskEvent(event streams.TaskEvent) {
	if s.taskHub == nil {
		return
	}
	if event.Metadata != nil && len(event.Metadata) == 0 {
		event.Metadata = nil
	}
	if event.Progress == 0 {
		event.Progress = statusProgress(event.Status)
	}
	s.taskHub.Publish(event)
}

func statusProgress(status string) int {
	switch status {
	case string(model.TaskStatusPending):
		return 0
	case string(model.TaskStatusLeased):
		return 10
	case string(model.TaskStatusRunning):
		return 60
	case string(model.TaskStatusSucceeded):
		return 100
	case string(model.TaskStatusFailed), string(model.TaskStatusCanceled):
		return 100
	default:
		return 0
	}
}

// PublishExternalEvent allows other components to push custom events.
func (s *Scheduler) PublishExternalEvent(event streams.TaskEvent) {
	s.publishTaskEvent(event)
}

func (s *Scheduler) requeueTask(ctx context.Context, task *model.Task) error {
	if err := s.queue.Requeue(ctx, task); err != nil {
		return err
	}
	if task != nil && task.Type == model.TaskType("bas") {
		s.adjustBASPending(1)
	}
	return nil
}

func (s *Scheduler) noteDequeuedTask(task *model.Task) {
	if task == nil || task.Type != model.TaskType("bas") {
		return
	}
	s.adjustBASPending(-1)
	s.observeBASQueueWait(task)
}

func (s *Scheduler) publishStats() {
	if s.taskHub == nil {
		return
	}
	stats := s.snapshotStats()
	s.taskHub.Publish(stats)
}

func (s *Scheduler) snapshotStats() streams.TaskEvent {
	s.mu.Lock()
	inFlight := s.totalInFlight
	bas := s.basInFlight
	basPending := s.basPending
	s.mu.Unlock()

	var depth int64
	if s.queue != nil {
		if d, err := s.queue.Len(context.Background()); err == nil {
			depth = d
		}
	}
	return streams.TaskEvent{
		Event:         "stats",
		InFlight:      inFlight,
		BASInFlight:   bas,
		BASQueueDepth: basPending,
		QueueDepth:    depth,
		UpdatedAt:     time.Now().UTC(),
	}
}

// EnqueueTask pushes a new task into the dispatch queue.
func (s *Scheduler) EnqueueTask(ctx context.Context, task *model.Task) error {
	if err := s.queue.Push(ctx, task); err != nil {
		return err
	}
	if task != nil && task.Type == model.TaskType("bas") {
		s.adjustBASPending(1)
	}
	s.observeQueueDepth(ctx)
	s.publishStats()
	return nil
}

// PrimeFromStore loads pending tasks from persistent store into the queue.
func (s *Scheduler) PrimeFromStore(ctx context.Context) error {
	tasks, err := s.store.ListPendingTasks(ctx, s.cfg.QueueCapacity)
	if err != nil {
		return err
	}
	for _, task := range tasks {
		if err := s.requeueTask(ctx, task); err != nil {
			return err
		}
	}
	s.observeQueueDepth(ctx)
	return nil
}

func (s *Scheduler) dequeueTask(ctx context.Context, capabilities []string) (*model.Task, error) {
	task, err := s.queue.Pop(ctx, capabilities)
	if err != nil {
		return nil, err
	}
	if task != nil {
		s.noteDequeuedTask(task)
		s.observeQueueDepth(ctx)
		return task, nil
	}
	if err := s.PrimeFromStore(ctx); err != nil {
		return nil, err
	}
	task, err = s.queue.Pop(ctx, capabilities)
	if task != nil {
		s.noteDequeuedTask(task)
		s.observeQueueDepth(ctx)
	}
	return task, err
}

func (s *Scheduler) reserveCapacity(agentID uuid.UUID) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cfg.MaxAgentConcurrency > 0 && s.agentInFlight[agentID] >= s.cfg.MaxAgentConcurrency {
		return false
	}
	if s.cfg.GlobalMaxConcurrency > 0 && s.totalInFlight >= s.cfg.GlobalMaxConcurrency {
		return false
	}
	s.agentInFlight[agentID]++
	s.totalInFlight++
	s.updateInFlightMetricLocked()
	return true
}

func (s *Scheduler) releaseCapacity(agentID uuid.UUID) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if count, ok := s.agentInFlight[agentID]; ok {
		if count > 1 {
			s.agentInFlight[agentID] = count - 1
		} else {
			delete(s.agentInFlight, agentID)
		}
	}
	if s.totalInFlight > 0 {
		s.totalInFlight--
	}
	s.updateInFlightMetricLocked()
}

func (s *Scheduler) reserveBAS(taskType model.TaskType) bool {
	if taskType != model.TaskType("bas") {
		return true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cfg.BASMaxConcurrency > 0 && s.basInFlight >= s.cfg.BASMaxConcurrency {
		return false
	}
	s.basInFlight++
	s.updateBASInFlightLocked()
	return true
}

func (s *Scheduler) releaseBAS(taskType model.TaskType) {
	if taskType != model.TaskType("bas") {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.basInFlight > 0 {
		s.basInFlight--
	}
	s.updateBASInFlightLocked()
}

func (s *Scheduler) updateInFlightMetricLocked() {
	if s.m != nil {
		s.m.TasksInFlight.Set(float64(s.totalInFlight))
	}
}

func (s *Scheduler) updateBASInFlightLocked() {
	if s.m != nil {
		s.m.BASInFlight.Set(float64(s.basInFlight))
	}
}

func (s *Scheduler) adjustBASPending(delta int64) {
	if delta == 0 {
		return
	}
	s.mu.Lock()
	s.basPending += delta
	if s.basPending < 0 {
		s.basPending = 0
	}
	s.updateBASPendingMetricLocked()
	s.mu.Unlock()
}

func (s *Scheduler) updateBASPendingMetricLocked() {
	if s.m != nil {
		if s.basPending < 0 {
			s.basPending = 0
		}
		s.m.BASBacklog.Set(float64(s.basPending))
	}
}

func (s *Scheduler) observeBASQueueWait(task *model.Task) {
	if s.m == nil || task == nil || task.Type != model.TaskType("bas") {
		return
	}
	if task.CreatedAt.IsZero() {
		return
	}
	wait := time.Since(task.CreatedAt)
	if wait >= 0 {
		s.m.BASQueueWait.Observe(wait.Seconds())
	}
}

func (s *Scheduler) observeQueueDepth(ctx context.Context) {
	if s.m == nil {
		return
	}
	depth, err := s.queue.Len(ctx)
	if err != nil {
		return
	}
	s.m.TaskQueueDepth.Set(float64(depth))
}

func (s *Scheduler) observeStatusChange(from, to model.TaskStatus) {
	if from == to {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if from != "" {
		if current := s.statusCounts[from]; current > 0 {
			s.statusCounts[from] = current - 1
		}
		if s.m != nil {
			s.m.TaskStatus.WithLabelValues(string(from)).Set(float64(s.statusCounts[from]))
		}
	}
	if to != "" {
		s.statusCounts[to]++
		if s.m != nil {
			s.m.TaskStatus.WithLabelValues(string(to)).Set(float64(s.statusCounts[to]))
		}
	}
}
