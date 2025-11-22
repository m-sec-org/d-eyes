package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/m-sec-org/d-eyes/server/internal/model"
	"github.com/m-sec-org/d-eyes/server/internal/store"
)

func TestMemoryStore_ListAgentsAndLatestRun(t *testing.T) {
	st := store.NewInMemoryStore()
	ctx := context.Background()

	agentID := uuid.New()
	agent := &model.Agent{
		ID:            agentID,
		Name:          "agent-1",
		Labels:        map[string]string{"env": "dev"},
		Capabilities:  []string{"respond"},
		Status:        model.AgentStatusOnline,
		LastHeartbeat: time.Now(),
	}
	if err := st.UpsertAgent(ctx, agent); err != nil {
		t.Fatalf("upsert agent: %v", err)
	}

	agents, err := st.ListAgents(ctx)
	if err != nil {
		t.Fatalf("list agents: %v", err)
	}
	if len(agents) != 1 {
		t.Fatalf("expected 1 agent, got %d", len(agents))
	}
	if agents[0].Name != "agent-1" {
		t.Fatalf("unexpected agent name: %s", agents[0].Name)
	}

	taskID := uuid.New()
	task := &model.Task{ID: taskID, Type: "respond", Priority: 1, Status: model.TaskStatusPending}
	if err := st.CreateTask(ctx, task); err != nil {
		t.Fatalf("create task: %v", err)
	}

	run1 := &model.TaskRun{ID: uuid.New(), TaskID: taskID, AgentID: agentID, LeaseID: uuid.New(), LeaseExpires: time.Now().Add(2 * time.Minute), Status: model.TaskStatusRunning}
	if err := st.CreateTaskRun(ctx, run1); err != nil {
		t.Fatalf("create run1: %v", err)
	}
	finished := time.Now()
	if err := st.UpdateTaskRunCompletion(ctx, run1.ID, model.TaskStatusSucceeded, finished, []byte(`{"ok":true}`), "", map[string]string{"module": "respond"}, 0, "", time.Time{}); err != nil {
		t.Fatalf("complete run1: %v", err)
	}

	latest, err := st.GetLatestTaskRun(ctx, taskID)
	if err != nil {
		t.Fatalf("latest run: %v", err)
	}
	if latest.Status != model.TaskStatusSucceeded {
		t.Fatalf("unexpected status: %s", latest.Status)
	}
}

func TestMemoryStore_TaskStatusAndRetry(t *testing.T) {
	st := store.NewInMemoryStore()
	ctx := context.Background()

	task := &model.Task{
		ID:       uuid.New(),
		Type:     model.TaskType("respond"),
		Priority: 1,
		Status:   model.TaskStatusPending,
	}
	require.NoError(t, st.CreateTask(ctx, task))

	require.NoError(t, st.UpdateTaskStatus(ctx, task.ID, model.TaskStatusRunning))

	got, err := st.GetTask(ctx, task.ID)
	require.NoError(t, err)
	require.Equal(t, model.TaskStatusRunning, got.Status)

	require.NoError(t, st.IncrementTaskRetry(ctx, task.ID))

	got, err = st.GetTask(ctx, task.ID)
	require.NoError(t, err)
	require.Equal(t, 1, got.RetryCount)
	require.Equal(t, model.TaskStatusRunning, got.Status)
}

func TestMemoryStore_TaskRunLifecycle(t *testing.T) {
	st := store.NewInMemoryStore()
	ctx := context.Background()

	taskID := uuid.New()
	agentID := uuid.New()
	task := &model.Task{ID: taskID, Type: "respond", Priority: 1, Status: model.TaskStatusPending}
	require.NoError(t, st.CreateTask(ctx, task))

	leaseID := uuid.New()
	run := &model.TaskRun{
		ID:           uuid.New(),
		TaskID:       taskID,
		AgentID:      agentID,
		LeaseID:      leaseID,
		LeaseExpires: time.Now().Add(time.Minute),
		Status:       model.TaskStatusLeased,
	}
	require.NoError(t, st.CreateTaskRun(ctx, run))

	fetched, err := st.GetTaskRunByLease(ctx, leaseID)
	require.NoError(t, err)
	require.Equal(t, model.TaskStatusLeased, fetched.Status)

	require.NoError(t, st.UpdateTaskRunStatusByLease(ctx, leaseID, model.TaskStatusRunning))

	fetched, err = st.GetTaskRunByLease(ctx, leaseID)
	require.NoError(t, err)
	require.Equal(t, model.TaskStatusRunning, fetched.Status)

	completedAt := time.Now()
	summary := []byte(`{"ok":true}`)
	require.NoError(t, st.UpdateTaskRunCompletion(ctx, run.ID, model.TaskStatusSucceeded, completedAt, summary, "", map[string]string{}, 0, "", time.Time{}))

	_, err = st.GetTaskRunByLease(ctx, leaseID)
	require.ErrorIs(t, err, store.ErrNotFound)

	latest, err := st.GetLatestTaskRun(ctx, taskID)
	require.NoError(t, err)
	require.Equal(t, model.TaskStatusSucceeded, latest.Status)
	require.Equal(t, []byte(`{"ok":true}`), latest.Summary)
}

func TestMemoryStore_UpdateAgentStatusStoresMetadata(t *testing.T) {
	st := store.NewInMemoryStore()
	ctx := context.Background()
	agent := &model.Agent{
		ID:     uuid.New(),
		Name:   "agent-meta",
		Labels: map[string]string{"env": "qa"},
	}
	require.NoError(t, st.UpsertAgent(ctx, agent))

	meta := map[string]string{
		"telemetry.cpu_percent": "45.0",
		"cache.respond_hits":    "3",
	}
	require.NoError(t, st.UpdateAgentStatus(ctx, agent.ID, model.AgentStatusOnline, time.Now(), 1.5, []string{"task-1"}, meta))

	updated, err := st.GetAgent(ctx, agent.ID)
	require.NoError(t, err)
	require.Equal(t, 1.5, updated.Load)
	require.Equal(t, []string{"task-1"}, updated.RunningTasks)
	require.Equal(t, "45.0", updated.Metadata["telemetry.cpu_percent"])
}
