package templates

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

func TestManagerCreateDeploy(t *testing.T) {
	ctx := context.Background()
	st := store.NewInMemoryStore()
	queue := memory.New()
	sched := scheduler.New(st, queue, schedulerConfig())

	manager, err := NewManager(Config{}, st, sched, nil)
	require.NoError(t, err)
	defer manager.Close()

	tmpl, err := manager.CreateTemplate(ctx, Template{
		Name:        "BAS 模板",
		TaskType:    "bas",
		Description: "测试模板",
		Flags: map[string]any{
			"scenario": "initial-access",
		},
		Metadata: map[string]string{
			"risk": "high",
		},
		Targets:  []string{"group-a"},
		Priority: 5,
	})
	require.NoError(t, err)
	require.NotEqual(t, uuid.Nil, tmpl.ID)

	result, err := manager.DeployTemplate(ctx, tmpl.ID, DeployRequest{
		CreatedBy: "tester",
	})
	require.NoError(t, err)
	require.Len(t, result.TaskIDs, 1)

	task, err := st.GetTask(ctx, result.TaskIDs[0])
	require.NoError(t, err)
	require.Equal(t, model.TaskType("bas"), task.Type)
	require.Equal(t, "tester", task.CreatedBy)
	require.Equal(t, "group-a", task.Metadata["target_agents"])
	require.Equal(t, tmpl.ID.String(), task.Metadata["template_id"])
}

func TestManagerSchedule(t *testing.T) {
	st := store.NewInMemoryStore()
	queue := memory.New()
	sched := scheduler.New(st, queue, schedulerConfig())

	manager, err := NewManager(Config{}, st, sched, nil)
	require.NoError(t, err)
	defer manager.Close()

	tmpl, err := manager.CreateTemplate(context.Background(), Template{
		Name:     "定时 BAS",
		TaskType: "bas",
		Flags: map[string]any{
			"scenario": "initial-access",
		},
		Schedule: &Schedule{
			Enabled:         true,
			IntervalMinutes: 1,
			Targets:         []string{"group-b"},
		},
	})
	require.NoError(t, err)

	tmpl.Schedule.NextRun = time.Now().Add(-time.Minute)
	_, err = manager.UpdateTemplate(context.Background(), tmpl.ID, *tmpl)
	require.NoError(t, err)

	manager.runDueSchedules()

	result, err := st.ListTasks(context.Background(), store.ListTasksOptions{Limit: 10})
	require.NoError(t, err)
	require.Len(t, result.Tasks, 1)
	require.Contains(t, result.Tasks[0].Metadata["target_agents"], "group-b")
}

func schedulerConfig() config.SchedulerConfig {
	return config.SchedulerConfig{
		LeaseTTL:          time.Minute,
		MaxRetries:        1,
		HeartbeatTimeout:  time.Minute,
		QueueCapacity:     10,
		LeasePollInterval: time.Millisecond,
	}
}
