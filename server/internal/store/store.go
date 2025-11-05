package store

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/m-sec-org/d-eyes/server/internal/model"
)

var ErrNotFound = errors.New("store: not found")

// Store defines the persistence contract required by scheduler and services.
type Store interface {
	UpsertAgent(ctx context.Context, agent *model.Agent) error
	GetAgentByName(ctx context.Context, name string) (*model.Agent, error)
	GetAgent(ctx context.Context, id uuid.UUID) (*model.Agent, error)
	UpdateAgentStatus(ctx context.Context, id uuid.UUID, status model.AgentStatus, heartbeat time.Time, load float64, running []string) error

	CreateTask(ctx context.Context, task *model.Task) error
	UpdateTaskStatus(ctx context.Context, taskID uuid.UUID, status model.TaskStatus) error
	IncrementTaskRetry(ctx context.Context, taskID uuid.UUID) error
	GetTask(ctx context.Context, id uuid.UUID) (*model.Task, error)
	ListPendingTasks(ctx context.Context, limit int) ([]*model.Task, error)
	ListTasks(ctx context.Context, statuses []model.TaskStatus, limit int) ([]*model.Task, error)
	ListAgents(ctx context.Context) ([]*model.Agent, error)
	Ping(ctx context.Context) error

	CreateTaskRun(ctx context.Context, run *model.TaskRun) error
	UpdateTaskRunStatusByLease(ctx context.Context, leaseID uuid.UUID, status model.TaskStatus) error
	UpdateTaskRunCompletion(ctx context.Context, runID uuid.UUID, status model.TaskStatus, finished time.Time, summary []byte, errMsg string) error
	GetTaskRunByLease(ctx context.Context, leaseID uuid.UUID) (*model.TaskRun, error)
	GetLatestTaskRun(ctx context.Context, taskID uuid.UUID) (*model.TaskRun, error)

	SaveArtifacts(ctx context.Context, artifacts []model.Artifact) error
}
