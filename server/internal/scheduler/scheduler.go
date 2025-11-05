package scheduler

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/m-sec-org/d-eyes/server/internal/config"
	"github.com/m-sec-org/d-eyes/server/internal/metrics"
	"github.com/m-sec-org/d-eyes/server/internal/model"
	"github.com/m-sec-org/d-eyes/server/internal/queue"
	"github.com/m-sec-org/d-eyes/server/internal/store"
)

var ErrNoTaskAvailable = errors.New("scheduler: no task available")

// Scheduler manages task leasing and dispatching.
type Scheduler struct {
	store store.Store
	queue queue.Queue
	cfg   config.SchedulerConfig
	m     *metrics.Metrics
}

func New(store store.Store, queue queue.Queue, cfg config.SchedulerConfig) *Scheduler {
	return &Scheduler{store: store, queue: queue, cfg: cfg}
}

// SetMetrics wires Prometheus collectors into the scheduler.
func (s *Scheduler) SetMetrics(m *metrics.Metrics) {
	s.m = m
}

// LeaseTask assigns a task to an agent, creating a TaskRun with lease TTL.
func (s *Scheduler) LeaseTask(ctx context.Context, agent *model.Agent) (*model.Task, *model.TaskRun, error) {
	task, err := s.dequeueTask(ctx, agent.Capabilities)
	if err != nil {
		return nil, nil, err
	}
	if task == nil {
		return nil, nil, ErrNoTaskAvailable
	}
	leaseID := uuid.New()
	run := &model.TaskRun{
		ID:           uuid.New(),
		TaskID:       task.ID,
		AgentID:      agent.ID,
		LeaseID:      leaseID,
		LeaseExpires: time.Now().Add(s.cfg.LeaseTTL),
		Status:       model.TaskStatusLeased,
	}
	if err := s.store.CreateTaskRun(ctx, run); err != nil {
		// push back into queue to avoid loss
		_ = s.queue.Requeue(ctx, task)
		return nil, nil, err
	}
	if err := s.store.UpdateTaskStatus(ctx, task.ID, model.TaskStatusLeased); err != nil {
		_ = s.queue.Requeue(ctx, task)
		return nil, nil, err
	}
	s.observeQueueDepth(ctx)
	if s.m != nil && !task.CreatedAt.IsZero() {
		wait := time.Since(task.CreatedAt)
		if wait >= 0 {
			s.m.TaskTimeToLease.Observe(wait.Seconds())
		}
	}
	return task, run, nil
}

func (s *Scheduler) HandleLeaseTimeout(ctx context.Context, run *model.TaskRun) error {
	if time.Now().Before(run.LeaseExpires) {
		return nil
	}
	if err := s.store.UpdateTaskStatus(ctx, run.TaskID, model.TaskStatusPending); err != nil {
		return err
	}
	if err := s.store.IncrementTaskRetry(ctx, run.TaskID); err != nil {
		return err
	}
	task, err := s.store.GetTask(ctx, run.TaskID)
	if err != nil {
		return err
	}
	if err := s.queue.Requeue(ctx, task); err != nil {
		return err
	}
	s.observeQueueDepth(ctx)
	return nil
}

func (s *Scheduler) CompleteTask(ctx context.Context, runID uuid.UUID, taskID uuid.UUID, status model.TaskStatus, summary []byte, errMsg string, artifacts []model.Artifact) error {
	now := time.Now()
	if err := s.store.UpdateTaskRunCompletion(ctx, runID, status, now, summary, errMsg); err != nil {
		return err
	}
	if err := s.store.UpdateTaskStatus(ctx, taskID, status); err != nil {
		return err
	}
	if len(artifacts) > 0 {
		if err := s.store.SaveArtifacts(ctx, artifacts); err != nil {
			return err
		}
	}
	return nil
}

func (s *Scheduler) MarkRunStarted(ctx context.Context, leaseID uuid.UUID) error {
	run, err := s.store.GetTaskRunByLease(ctx, leaseID)
	if err != nil {
		return err
	}
	if err := s.store.UpdateTaskRunStatusByLease(ctx, leaseID, model.TaskStatusRunning); err != nil {
		return err
	}
	if err := s.store.UpdateTaskStatus(ctx, run.TaskID, model.TaskStatusRunning); err != nil {
		return err
	}
	return nil
}

// EnqueueTask pushes a new task into the dispatch queue.
func (s *Scheduler) EnqueueTask(ctx context.Context, task *model.Task) error {
	if err := s.queue.Push(ctx, task); err != nil {
		return err
	}
	s.observeQueueDepth(ctx)
	return nil
}

// PrimeFromStore loads pending tasks from persistent store into the queue.
func (s *Scheduler) PrimeFromStore(ctx context.Context) error {
	tasks, err := s.store.ListPendingTasks(ctx, s.cfg.QueueCapacity)
	if err != nil {
		return err
	}
	for _, task := range tasks {
		if err := s.queue.Requeue(ctx, task); err != nil {
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
		s.observeQueueDepth(ctx)
		return task, nil
	}
	if err := s.PrimeFromStore(ctx); err != nil {
		return nil, err
	}
	task, err = s.queue.Pop(ctx, capabilities)
	if task != nil {
		s.observeQueueDepth(ctx)
	}
	return task, err
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
