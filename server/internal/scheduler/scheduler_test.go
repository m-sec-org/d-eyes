package scheduler_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/m-sec-org/d-eyes/server/internal/config"
	"github.com/m-sec-org/d-eyes/server/internal/model"
	"github.com/m-sec-org/d-eyes/server/internal/queue/memory"
	"github.com/m-sec-org/d-eyes/server/internal/scheduler"
	"github.com/m-sec-org/d-eyes/server/internal/store"
)

func TestLeaseAndCompleteLifecycle(t *testing.T) {
	ctx := context.Background()
	st := store.NewInMemoryStore()

	agent := &model.Agent{
		ID:            uuid.New(),
		Name:          "agent-1",
		Capabilities:  []string{"respond"},
		Status:        model.AgentStatusOnline,
		LastHeartbeat: time.Now(),
	}
	require.NoError(t, st.UpsertAgent(ctx, agent))

	task := &model.Task{
		ID:       uuid.New(),
		Type:     model.TaskType("respond"),
		Priority: 1,
		Payload:  []byte(`{"profile":"quick"}`),
		Status:   model.TaskStatusPending,
	}
	require.NoError(t, st.CreateTask(ctx, task))

	queue := memory.New()
	sched := scheduler.New(st, queue, config.SchedulerConfig{
		LeaseTTL:          2 * time.Second,
		MaxRetries:        3,
		HeartbeatTimeout:  5 * time.Second,
		QueueCapacity:     10,
		LeasePollInterval: time.Millisecond,
	})
	require.NoError(t, sched.PrimeFromStore(ctx))

	leasedTask, run, err := sched.LeaseTask(ctx, agent)
	require.NoError(t, err)
	require.Equal(t, task.ID, leasedTask.ID)
	require.NoError(t, sched.MarkRunStarted(ctx, run.LeaseID))

	require.NoError(t, sched.CompleteTask(ctx, run.ID, run.TaskID, model.TaskStatusSucceeded, []byte(`{"ok":true}`), "", nil))

	storedTask, err := st.GetTask(ctx, task.ID)
	require.NoError(t, err)
	require.Equal(t, model.TaskStatusSucceeded, storedTask.Status)
}

func TestLeaseTask_NoTaskAvailable(t *testing.T) {
	ctx := context.Background()
	st := store.NewInMemoryStore()
	queue := memory.New()
	sched := scheduler.New(st, queue, config.SchedulerConfig{
		LeaseTTL:          time.Second,
		MaxRetries:        1,
		HeartbeatTimeout:  time.Second,
		QueueCapacity:     10,
		LeasePollInterval: time.Millisecond,
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

func TestHandleLeaseTimeout(t *testing.T) {
	ctx := context.Background()
	st := store.NewInMemoryStore()
	queue := memory.New()
	sched := scheduler.New(st, queue, config.SchedulerConfig{
		LeaseTTL:          time.Second,
		MaxRetries:        3,
		HeartbeatTimeout:  time.Second,
		QueueCapacity:     10,
		LeasePollInterval: time.Millisecond,
	})

	task := &model.Task{
		ID:       uuid.New(),
		Type:     model.TaskType("respond"),
		Priority: 1,
		Status:   model.TaskStatusLeased,
	}
	require.NoError(t, st.CreateTask(ctx, task))

	leaseID := uuid.New()
	run := &model.TaskRun{
		ID:           uuid.New(),
		TaskID:       task.ID,
		AgentID:      uuid.New(),
		LeaseID:      leaseID,
		LeaseExpires: time.Now().Add(-1 * time.Minute),
		Status:       model.TaskStatusLeased,
	}
	require.NoError(t, st.CreateTaskRun(ctx, run))

	require.NoError(t, sched.HandleLeaseTimeout(ctx, run))

	updatedTask, err := st.GetTask(ctx, task.ID)
	require.NoError(t, err)
	require.Equal(t, model.TaskStatusPending, updatedTask.Status)
	require.Equal(t, 1, updatedTask.RetryCount)

	agent := &model.Agent{
		ID:           uuid.New(),
		Name:         "agent-retry",
		Capabilities: []string{"respond"},
		Status:       model.AgentStatusOnline,
	}
	require.NoError(t, st.UpsertAgent(ctx, agent))

	leasedTask, _, err := sched.LeaseTask(ctx, agent)
	require.NoError(t, err)
	require.Equal(t, task.ID, leasedTask.ID)
}
