package scheduler_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/require"

	"github.com/m-sec-org/d-eyes/server/internal/alerts"
	"github.com/m-sec-org/d-eyes/server/internal/audit"
	"github.com/m-sec-org/d-eyes/server/internal/config"
	"github.com/m-sec-org/d-eyes/server/internal/metrics"
	"github.com/m-sec-org/d-eyes/server/internal/model"
	"github.com/m-sec-org/d-eyes/server/internal/queue/memory"
	"github.com/m-sec-org/d-eyes/server/internal/scheduler"
	"github.com/m-sec-org/d-eyes/server/internal/store"
	"github.com/m-sec-org/d-eyes/server/internal/streams"
)

func TestLeaseAndCompleteLifecycle(t *testing.T) {
	ctx := context.Background()
	st := store.NewInMemoryStore()
	queue := memory.New()
	cfg := config.SchedulerConfig{
		LeaseTTL:             2 * time.Second,
		MaxRetries:           3,
		HeartbeatTimeout:     5 * time.Second,
		QueueCapacity:        10,
		LeasePollInterval:    time.Millisecond,
		MaxAgentConcurrency:  2,
		GlobalMaxConcurrency: 0,
	}
	sched := scheduler.New(st, queue, cfg)

	agent := &model.Agent{
		ID:            uuid.New(),
		Name:          "agent-1",
		Capabilities:  []string{"respond"},
		Status:        model.AgentStatusOnline,
		LastHeartbeat: time.Now(),
	}
	require.NoError(t, st.UpsertAgent(ctx, agent))

	task := &model.Task{
		ID:        uuid.New(),
		Type:      model.TaskType("respond"),
		Profile:   "quick",
		Priority:  1,
		Payload:   []byte(`{"profile":"quick"}`),
		Status:    model.TaskStatusPending,
		CreatedAt: time.Now().Add(-time.Second),
	}
	require.NoError(t, st.CreateTask(ctx, task))
	require.NoError(t, sched.PrimeFromStore(ctx))

	leasedTask, run, err := sched.LeaseTask(ctx, agent)
	require.NoError(t, err)
	require.Equal(t, task.ID, leasedTask.ID)
	require.NoError(t, sched.MarkRunStarted(ctx, run.LeaseID))

	runAfterStart, err := st.GetTaskRunByLease(ctx, run.LeaseID)
	require.NoError(t, err)
	require.Equal(t, model.TaskStatusRunning, runAfterStart.Status)

	require.NoError(t, sched.CompleteTask(ctx, runAfterStart, model.TaskStatusSucceeded, []byte(`{"ok":true}`), "", map[string]string{"module": "respond"}, 0, "", nil))

	storedTask, err := st.GetTask(ctx, task.ID)
	require.NoError(t, err)
	require.Equal(t, model.TaskStatusSucceeded, storedTask.Status)
}

func TestLeaseTask_NoTaskAvailable(t *testing.T) {
	ctx := context.Background()
	st := store.NewInMemoryStore()
	queue := memory.New()
	sched := scheduler.New(st, queue, config.SchedulerConfig{
		LeaseTTL:             time.Second,
		MaxRetries:           1,
		HeartbeatTimeout:     time.Second,
		QueueCapacity:        10,
		LeasePollInterval:    time.Millisecond,
		MaxAgentConcurrency:  1,
		GlobalMaxConcurrency: 0,
	})

	agent := &model.Agent{
		ID:           uuid.New(),
		Name:         "agent-empty",
		Capabilities: []string{"respond"},
		Status:       model.AgentStatusOnline,
	}
	require.NoError(t, st.UpsertAgent(ctx, agent))

	task, run, err := sched.LeaseTask(ctx, agent)
	require.ErrorIs(t, err, scheduler.ErrNoTaskAvailable)
	require.Nil(t, task)
	require.Nil(t, run)
}

func TestLeaseTask_RespectsAgentConcurrency(t *testing.T) {
	ctx := context.Background()
	st := store.NewInMemoryStore()
	queue := memory.New()
	sched := scheduler.New(st, queue, config.SchedulerConfig{
		LeaseTTL:             2 * time.Second,
		MaxRetries:           1,
		HeartbeatTimeout:     time.Second,
		QueueCapacity:        10,
		LeasePollInterval:    time.Millisecond,
		MaxAgentConcurrency:  1,
		GlobalMaxConcurrency: 0,
	})

	agent := &model.Agent{
		ID:            uuid.New(),
		Name:          "agent-1",
		Capabilities:  []string{"respond"},
		Status:        model.AgentStatusOnline,
		LastHeartbeat: time.Now(),
	}
	require.NoError(t, st.UpsertAgent(ctx, agent))

	task1 := &model.Task{ID: uuid.New(), Type: model.TaskType("respond"), Priority: 1, Status: model.TaskStatusPending}
	task2 := &model.Task{ID: uuid.New(), Type: model.TaskType("respond"), Priority: 2, Status: model.TaskStatusPending}
	require.NoError(t, st.CreateTask(ctx, task1))
	require.NoError(t, st.CreateTask(ctx, task2))
	require.NoError(t, sched.EnqueueTask(ctx, task1))
	require.NoError(t, sched.EnqueueTask(ctx, task2))

	firstTask, firstRun, err := sched.LeaseTask(ctx, agent)
	require.NoError(t, err)
	require.Equal(t, task1.ID, firstTask.ID)

	_, _, err = sched.LeaseTask(ctx, agent)
	require.ErrorIs(t, err, scheduler.ErrAgentAtCapacity)

	require.NoError(t, sched.MarkRunStarted(ctx, firstRun.LeaseID))
	runStored, err := st.GetTaskRunByLease(ctx, firstRun.LeaseID)
	require.NoError(t, err)
	require.NoError(t, sched.CompleteTask(ctx, runStored, model.TaskStatusSucceeded, nil, "", nil, 0, "", nil))

	nextTask, nextRun, err := sched.LeaseTask(ctx, agent)
	require.NoError(t, err)
	require.Equal(t, task2.ID, nextTask.ID)
	require.NotNil(t, nextRun)
}

func TestLeaseTask_BASPolicyEnforcement(t *testing.T) {
	ctx := context.Background()
	st := store.NewInMemoryStore()
	queue := memory.New()
	sched := scheduler.New(st, queue, config.SchedulerConfig{
		LeaseTTL:             time.Second,
		MaxRetries:           1,
		HeartbeatTimeout:     time.Second,
		QueueCapacity:        10,
		LeasePollInterval:    time.Millisecond,
		MaxAgentConcurrency:  2,
		GlobalMaxConcurrency: 0,
	})

	task := &model.Task{
		ID:       uuid.New(),
		Type:     model.TaskType("bas"),
		Priority: 1,
		Status:   model.TaskStatusPending,
		Metadata: map[string]string{
			"network_boundaries":       "dmz,prod",
			"scenario_required_labels": "zone=dmz,tenant=blue",
		},
	}
	require.NoError(t, st.CreateTask(ctx, task))
	require.NoError(t, sched.PrimeFromStore(ctx))

	agentNoBoundary := &model.Agent{
		ID:           uuid.New(),
		Name:         "agent-no-boundary",
		Capabilities: []string{"bas"},
		Labels:       map[string]string{"zone": "lab"},
		Status:       model.AgentStatusOnline,
	}
	require.NoError(t, st.UpsertAgent(ctx, agentNoBoundary))

	leasedTask, run, err := sched.LeaseTask(ctx, agentNoBoundary)
	require.ErrorIs(t, err, scheduler.ErrNoTaskAvailable)
	require.Nil(t, leasedTask)
	require.Nil(t, run)

	agentMissingLabel := &model.Agent{
		ID:           uuid.New(),
		Name:         "agent-missing-label",
		Capabilities: []string{"bas"},
		Labels:       map[string]string{"network_boundary": "dmz"},
		Status:       model.AgentStatusOnline,
	}
	require.NoError(t, st.UpsertAgent(ctx, agentMissingLabel))

	leasedTask, run, err = sched.LeaseTask(ctx, agentMissingLabel)
	require.ErrorIs(t, err, scheduler.ErrNoTaskAvailable)
	require.Nil(t, leasedTask)
	require.Nil(t, run)

	agentMatches := &model.Agent{
		ID:           uuid.New(),
		Name:         "agent-matches",
		Capabilities: []string{"bas"},
		Labels: map[string]string{
			"network_boundary": "prod",
			"tenant":           "blue",
			"zone":             "dmz",
		},
		Status:        model.AgentStatusOnline,
		LastHeartbeat: time.Now(),
	}
	require.NoError(t, st.UpsertAgent(ctx, agentMatches))

	leasedTask, run, err = sched.LeaseTask(ctx, agentMatches)
	require.NoError(t, err)
	require.NotNil(t, leasedTask)
	require.Equal(t, task.ID, leasedTask.ID)
	require.NotNil(t, run)
}

func TestLeaseTask_BASMaxConcurrencyQueuesTask(t *testing.T) {
	ctx := context.Background()
	st := store.NewInMemoryStore()
	queue := memory.New()
	cfg := config.SchedulerConfig{
		LeaseTTL:             time.Second,
		MaxRetries:           1,
		HeartbeatTimeout:     time.Second,
		QueueCapacity:        10,
		LeasePollInterval:    time.Millisecond,
		MaxAgentConcurrency:  2,
		GlobalMaxConcurrency: 0,
		BASMaxConcurrency:    1,
	}
	sched := scheduler.New(st, queue, cfg)

	reg := prometheus.NewRegistry()
	m := metrics.New(reg)
	sched.SetMetrics(m)

	task1 := &model.Task{
		ID:        uuid.New(),
		Type:      model.TaskType("bas"),
		Priority:  1,
		Status:    model.TaskStatusPending,
		CreatedAt: time.Now().Add(-time.Second),
	}
	task2 := &model.Task{
		ID:        uuid.New(),
		Type:      model.TaskType("bas"),
		Priority:  2,
		Status:    model.TaskStatusPending,
		CreatedAt: time.Now().Add(-2 * time.Second),
	}
	require.NoError(t, st.CreateTask(ctx, task1))
	require.NoError(t, st.CreateTask(ctx, task2))
	require.NoError(t, sched.PrimeFromStore(ctx))

	agent1 := &model.Agent{ID: uuid.New(), Name: "agent-1", Capabilities: []string{"bas"}, Status: model.AgentStatusOnline, LastHeartbeat: time.Now()}
	agent2 := &model.Agent{ID: uuid.New(), Name: "agent-2", Capabilities: []string{"bas"}, Status: model.AgentStatusOnline, LastHeartbeat: time.Now()}
	require.NoError(t, st.UpsertAgent(ctx, agent1))
	require.NoError(t, st.UpsertAgent(ctx, agent2))

	firstTask, firstRun, err := sched.LeaseTask(ctx, agent1)
	require.NoError(t, err)
	pendingID := task2.ID
	if firstTask.ID == task2.ID {
		pendingID = task1.ID
	}

	_, _, err = sched.LeaseTask(ctx, agent2)
	require.ErrorIs(t, err, scheduler.ErrNoTaskAvailable)

	depth, err := queue.Len(ctx)
	require.NoError(t, err)
	require.Equal(t, int64(1), depth)
	require.Equal(t, 1.0, counterValue(t, reg, "d_eyes_bas_queue_backlog", nil))

	require.NoError(t, sched.MarkRunStarted(ctx, firstRun.LeaseID))
	runStored, err := st.GetTaskRunByLease(ctx, firstRun.LeaseID)
	require.NoError(t, err)
	require.NoError(t, sched.CompleteTask(ctx, runStored, model.TaskStatusSucceeded, nil, "", nil, 0, "", nil))

	secondTask, secondRun, err := sched.LeaseTask(ctx, agent2)
	require.NoError(t, err)
	require.Equal(t, pendingID, secondTask.ID)
	require.NotNil(t, secondRun)
	require.Equal(t, 0.0, counterValue(t, reg, "d_eyes_bas_queue_backlog", nil))
}

func TestHandleLeaseTimeout_MaxRetries(t *testing.T) {
	ctx := context.Background()
	st := store.NewInMemoryStore()
	queue := memory.New()
	sched := scheduler.New(st, queue, config.SchedulerConfig{
		LeaseTTL:             250 * time.Millisecond,
		MaxRetries:           1,
		HeartbeatTimeout:     time.Second,
		QueueCapacity:        10,
		LeasePollInterval:    time.Millisecond,
		MaxAgentConcurrency:  1,
		GlobalMaxConcurrency: 0,
	})

	agent := &model.Agent{
		ID:            uuid.New(),
		Name:          "agent-1",
		Capabilities:  []string{"respond"},
		Status:        model.AgentStatusOnline,
		LastHeartbeat: time.Now(),
	}
	require.NoError(t, st.UpsertAgent(ctx, agent))

	task := &model.Task{ID: uuid.New(), Type: model.TaskType("respond"), Priority: 1, Status: model.TaskStatusPending}
	require.NoError(t, st.CreateTask(ctx, task))
	require.NoError(t, sched.PrimeFromStore(ctx))

	// First attempt
	_, run1, err := sched.LeaseTask(ctx, agent)
	require.NoError(t, err)
	require.NoError(t, sched.MarkRunStarted(ctx, run1.LeaseID))
	run1Stored, err := st.GetTaskRunByLease(ctx, run1.LeaseID)
	require.NoError(t, err)
	time.Sleep(300 * time.Millisecond)
	require.NoError(t, sched.HandleLeaseTimeout(ctx, run1Stored))

	taskRecord, err := st.GetTask(ctx, task.ID)
	require.NoError(t, err)
	require.Equal(t, model.TaskStatusPending, taskRecord.Status)
	require.Equal(t, 1, taskRecord.RetryCount)

	// Second attempt should exceed retries and fail the task
	_, run2, err := sched.LeaseTask(ctx, agent)
	require.NoError(t, err)
	require.NoError(t, sched.MarkRunStarted(ctx, run2.LeaseID))
	run2Stored, err := st.GetTaskRunByLease(ctx, run2.LeaseID)
	require.NoError(t, err)
	time.Sleep(300 * time.Millisecond)
	require.NoError(t, sched.HandleLeaseTimeout(ctx, run2Stored))

	taskFinal, err := st.GetTask(ctx, task.ID)
	require.NoError(t, err)
	require.Equal(t, model.TaskStatusFailed, taskFinal.Status)
	require.Equal(t, 2, taskFinal.RetryCount)
}

func TestCompleteTaskBASMetricsAuditAndAlerts(t *testing.T) {
	ctx := context.Background()
	st := store.NewInMemoryStore()
	queue := memory.New()
	cfg := config.SchedulerConfig{
		LeaseTTL:             time.Minute,
		MaxRetries:           1,
		HeartbeatTimeout:     time.Minute,
		QueueCapacity:        10,
		LeasePollInterval:    time.Millisecond,
		MaxAgentConcurrency:  2,
		GlobalMaxConcurrency: 0,
	}
	sched := scheduler.New(st, queue, cfg)

	reg := prometheus.NewRegistry()
	m := metrics.New(reg)
	sched.SetMetrics(m)

	auditStub := &stubAuditRecorder{}
	sched.SetAudit(auditStub)

	alertStub := &stubNotifier{}
	sched.SetAlerts(alertStub)

	hub := streams.NewTaskHub()
	sched.SetTaskHub(hub)
	subCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	events, stop := hub.Subscribe(subCtx)
	defer stop()

	agent := &model.Agent{
		ID:            uuid.New(),
		Name:          "agent-bas",
		Capabilities:  []string{"bas"},
		Status:        model.AgentStatusOnline,
		LastHeartbeat: time.Now(),
	}
	require.NoError(t, st.UpsertAgent(ctx, agent))

	task := &model.Task{
		ID:        uuid.New(),
		Type:      model.TaskType("bas"),
		Status:    model.TaskStatusPending,
		CreatedAt: time.Now().Add(-time.Second),
	}
	require.NoError(t, st.CreateTask(ctx, task))

	run := &model.TaskRun{
		ID:        uuid.New(),
		TaskID:    task.ID,
		TaskType:  task.Type,
		AgentID:   agent.ID,
		LeaseID:   uuid.New(),
		Status:    model.TaskStatusRunning,
		StartedAt: ptrTime(time.Now().Add(-2 * time.Second)),
	}
	require.NoError(t, st.CreateTaskRun(ctx, run))

	metadata := map[string]string{
		"scenario_id":               "initial-access",
		"scenario_name":             "初始访问与持久化模拟",
		"sandbox_enabled":           "true",
		"sandbox_executed":          "true",
		"sandbox_fallback":          "true",
		"sandbox_approval_required": "true",
		"sandbox_approved":          "false",
	}
	summary := []byte(`{"summary":{"notes":["download failed"],"risks":{"high":1},"error_message":"sandbox runtime unavailable"}}`)

	require.NoError(t, sched.CompleteTask(ctx, run, model.TaskStatusFailed, summary, "sandbox runtime unavailable", metadata, 1, "bas.sandbox_unavailable", nil))

	require.Equal(t, 1.0, counterValue(t, reg, "d_eyes_bas_scenarios_total", map[string]string{
		"scenario_id":  "initial-access",
		"status":       string(model.TaskStatusFailed),
		"sandbox_used": "true",
	}))
	require.Equal(t, 1.0, counterValue(t, reg, "d_eyes_bas_sandbox_fallback_total", map[string]string{
		"scenario_id": "initial-access",
	}))
	require.Equal(t, 1.0, counterValue(t, reg, "d_eyes_bas_sandbox_approvals_total", map[string]string{
		"approved": "false",
	}))

	require.Len(t, auditStub.events, 1)
	auditEvent := auditStub.events[0]
	require.Equal(t, "initial-access", auditEvent.ScenarioID)
	require.True(t, auditEvent.SandboxFallback)
	require.True(t, auditEvent.ApprovalRequired)
	require.False(t, auditEvent.ApprovalGranted)

	require.Len(t, alertStub.events, 1)
	alertEvent := alertStub.events[0]
	require.Equal(t, "initial-access", alertEvent.ScenarioID)
	require.Equal(t, "failed", alertEvent.Status)
	require.True(t, alertEvent.SandboxFallback)

	select {
	case evt := <-events:
		require.Equal(t, "completed", evt.Event)
		require.Equal(t, "initial-access", evt.ScenarioID)
	default:
		t.Fatalf("expected task event on completion")
	}
}

type stubAuditRecorder struct {
	events []audit.Event
}

func (s *stubAuditRecorder) Record(event audit.Event) error {
	s.events = append(s.events, event)
	return nil
}

type stubNotifier struct {
	events []alerts.Event
}

func (s *stubNotifier) NotifyBAS(event alerts.Event) {
	s.events = append(s.events, event)
}

func ptrTime(t time.Time) *time.Time {
	return &t
}

func counterValue(t *testing.T, reg *prometheus.Registry, metricName string, labels map[string]string) float64 {
	t.Helper()
	mfs, err := reg.Gather()
	require.NoError(t, err)
	for _, mf := range mfs {
		if mf.GetName() != metricName {
			continue
		}
		for _, m := range mf.GetMetric() {
			if matchLabels(m, labels) {
				if m.GetCounter() != nil {
					return m.GetCounter().GetValue()
				}
				if m.GetGauge() != nil {
					return m.GetGauge().GetValue()
				}
			}
		}
	}
	t.Fatalf("metric %s with labels %v not found", metricName, labels)
	return 0
}

func matchLabels(metric *dto.Metric, expected map[string]string) bool {
	if len(expected) == 0 {
		return true
	}
	found := make(map[string]string, len(metric.GetLabel()))
	for _, pair := range metric.GetLabel() {
		found[pair.GetName()] = pair.GetValue()
	}
	for k, v := range expected {
		if found[k] != v {
			return false
		}
	}
	return true
}
