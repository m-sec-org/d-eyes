package memory

import (
	"context"
	"errors"
	"sync"

	"github.com/m-sec-org/d-eyes/server/internal/model"
	"github.com/m-sec-org/d-eyes/server/internal/queue"
)

type option func(*MemoryQueue)

type MemoryQueue struct {
	mu     sync.Mutex
	tasks  []*model.Task
	closed bool
}

func New(opts ...option) *MemoryQueue {
	mq := &MemoryQueue{}
	for _, opt := range opts {
		opt(mq)
	}
	return mq
}

func (m *MemoryQueue) Push(_ context.Context, task *model.Task) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return errors.New("queue closed")
	}
	cp := *task
	m.tasks = append(m.tasks, &cp)
	return nil
}

func (m *MemoryQueue) Requeue(ctx context.Context, task *model.Task) error {
	return m.Push(ctx, task)
}

func (m *MemoryQueue) Pop(_ context.Context, caps []string) (*model.Task, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, task := range m.tasks {
		if queue.MatchCapabilities(task, caps) {
			m.tasks = append(m.tasks[:i], m.tasks[i+1:]...)
			cp := *task
			return &cp, nil
		}
	}
	return nil, nil
}

func (m *MemoryQueue) Len(_ context.Context) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return int64(len(m.tasks)), nil
}

func (m *MemoryQueue) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	m.tasks = nil
	return nil
}

var _ queue.Queue = (*MemoryQueue)(nil)
