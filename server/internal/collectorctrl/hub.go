package collectorctrl

import (
	"context"
	"sync"
	"time"

	"github.com/m-sec-org/d-eyes/server/internal/model"
)

// Hub provides pub/sub for collector status updates.
type Hub struct {
	mu          sync.RWMutex
	subscribers map[int]chan model.CollectorStatusSnapshot
	nextID      int
	closed      bool
}

// NewHub constructs a Hub.
func NewHub() *Hub {
	return &Hub{
		subscribers: make(map[int]chan model.CollectorStatusSnapshot),
	}
}

// Publish broadcasts the status to subscribers.
func (h *Hub) Publish(status model.CollectorStatusSnapshot) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	if h.closed {
		return
	}
	if status.UpdatedAt.IsZero() {
		status.UpdatedAt = time.Now().UTC()
	}
	for _, ch := range h.subscribers {
		select {
		case ch <- status:
		default:
		}
	}
}

// Subscribe registers a listener.
func (h *Hub) Subscribe(ctx context.Context) (<-chan model.CollectorStatusSnapshot, func()) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		ch := make(chan model.CollectorStatusSnapshot)
		close(ch)
		return ch, func() {}
	}
	id := h.nextID
	h.nextID++
	ch := make(chan model.CollectorStatusSnapshot, 32)
	h.subscribers[id] = ch

	cancel := func() {
		h.mu.Lock()
		if sub, ok := h.subscribers[id]; ok {
			delete(h.subscribers, id)
			close(sub)
		}
		h.mu.Unlock()
	}

	go func() {
		<-ctx.Done()
		cancel()
	}()

	return ch, cancel
}

// Close shuts down the hub.
func (h *Hub) Close() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return
	}
	h.closed = true
	for id, ch := range h.subscribers {
		delete(h.subscribers, id)
		close(ch)
	}
}
