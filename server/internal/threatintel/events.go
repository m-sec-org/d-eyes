package threatintel

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// Hub is a lightweight pub/sub hub for ThreatIntel events.
type Hub struct {
	mu          sync.RWMutex
	subscribers map[int]chan Event
	nextID      int
	closed      bool
}

// NewHub constructs an events hub.
func NewHub() *Hub {
	return &Hub{
		subscribers: make(map[int]chan Event),
	}
}

// Publish fan-outs an event to all subscribers.
func (h *Hub) Publish(event Event) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	if h.closed {
		return
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}
	for _, ch := range h.subscribers {
		select {
		case ch <- event:
		default:
		}
	}
}

// Subscribe registers a listener.
func (h *Hub) Subscribe(ctx context.Context) (<-chan Event, func()) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		ch := make(chan Event)
		close(ch)
		return ch, func() {}
	}
	id := h.nextID
	h.nextID++
	ch := make(chan Event, 64)
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

// Close tears down the hub.
func (h *Hub) Close() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return
	}
	h.closed = true
	for id, sub := range h.subscribers {
		delete(h.subscribers, id)
		close(sub)
	}
}

// SSEHandler renders events via Server-Sent Events.
func SSEHandler(hub *Hub) gin.HandlerFunc {
	return func(c *gin.Context) {
		if hub == nil {
			c.Status(http.StatusNotImplemented)
			return
		}
		ctx := c.Request.Context()
		events, cancel := hub.Subscribe(ctx)
		defer cancel()

		c.Writer.Header().Set("Content-Type", "text/event-stream")
		c.Writer.Header().Set("Cache-Control", "no-cache")
		c.Writer.Header().Set("Connection", "keep-alive")
		c.Writer.Flush()

		for event := range events {
			data, err := json.Marshal(event)
			if err != nil {
				continue
			}
			if _, err := c.Writer.Write([]byte("data: ")); err != nil {
				return
			}
			if _, err := c.Writer.Write(data); err != nil {
				return
			}
			if _, err := c.Writer.Write([]byte("\n\n")); err != nil {
				return
			}
			c.Writer.Flush()
		}
	}
}
