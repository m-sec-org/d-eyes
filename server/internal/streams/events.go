package streams

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// TaskEvent 描述任务状态或统计事件。
type TaskEvent struct {
	Event         string            `json:"event"`
	TaskID        string            `json:"task_id,omitempty"`
	TaskType      string            `json:"task_type,omitempty"`
	Status        string            `json:"status,omitempty"`
	AgentID       string            `json:"agent_id,omitempty"`
	ScenarioID    string            `json:"scenario_id,omitempty"`
	ScenarioName  string            `json:"scenario_name,omitempty"`
	Metadata      map[string]string `json:"metadata,omitempty"`
	InFlight      int               `json:"in_flight,omitempty"`
	BASInFlight   int               `json:"bas_in_flight,omitempty"`
	BASQueueDepth int64             `json:"bas_queue_depth,omitempty"`
	QueueDepth    int64             `json:"queue_depth,omitempty"`
	Progress      int               `json:"progress,omitempty"`
	Message       string            `json:"message,omitempty"`
	Action        string            `json:"action,omitempty"`
	Actor         string            `json:"actor,omitempty"`
	Severity      string            `json:"severity,omitempty"`
	UpdatedAt     time.Time         `json:"updated_at"`
}

// Hub 负责事件的订阅与分发。
type Hub struct {
	mu          sync.RWMutex
	subscribers map[int]chan TaskEvent
	nextID      int
	closed      bool
}

// NewTaskHub 构造 Hub。
func NewTaskHub() *Hub {
	return &Hub{
		subscribers: make(map[int]chan TaskEvent),
	}
}

// Publish 向所有订阅者广播事件。
func (h *Hub) Publish(event TaskEvent) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	if h.closed {
		return
	}
	if event.UpdatedAt.IsZero() {
		event.UpdatedAt = time.Now().UTC()
	}
	for _, ch := range h.subscribers {
		select {
		case ch <- event:
		default:
			// 丢弃，避免阻塞
		}
	}
}

// Subscribe 注册订阅，返回事件通道与取消函数。
func (h *Hub) Subscribe(ctx context.Context) (<-chan TaskEvent, func()) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		ch := make(chan TaskEvent)
		close(ch)
		return ch, func() {}
	}
	id := h.nextID
	h.nextID++
	ch := make(chan TaskEvent, 32)
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

// Close 关闭 Hub。
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

// SSEHandler 返回 SSE 处理函数。
func SSEHandler(hub *Hub) func(*gin.Context) {
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
