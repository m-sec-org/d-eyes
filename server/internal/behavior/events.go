package behavior

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/m-sec-org/d-eyes/server/internal/model"
)

// Event represents anomaly stream payloads.
type Event struct {
	Event     string              `json:"event"`
	Anomaly   *model.Anomaly      `json:"anomaly,omitempty"`
	Graph     *model.AnomalyGraph `json:"graph,omitempty"`
	Timestamp time.Time           `json:"timestamp"`
}

// Hub manages anomaly stream subscribers.
type Hub struct {
	mu          sync.RWMutex
	subscribers map[int]chan Event
	nextID      int
	closed      bool
}

// NewHub constructs a new anomaly event hub.
func NewHub() *Hub {
	return &Hub{
		subscribers: make(map[int]chan Event),
	}
}

// Publish broadcasts event to subscribers.
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

// Emit clones anomaly/graph payloads then publishes the event.
func (h *Hub) Emit(eventType string, anomaly *model.Anomaly, graph *model.AnomalyGraph) {
	if h == nil {
		return
	}
	evt := Event{
		Event:     eventType,
		Timestamp: time.Now().UTC(),
	}
	if anomaly != nil {
		evt.Anomaly = cloneAnomaly(anomaly)
	}
	if graph != nil {
		evt.Graph = cloneGraph(graph)
	}
	h.Publish(evt)
}

// Subscribe registers a new listener.
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

// SSEHandler renders anomaly events as server-sent events.
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

func cloneAnomaly(src *model.Anomaly) *model.Anomaly {
	if src == nil {
		return nil
	}
	cp := *src
	if src.Summary != nil {
		cp.Summary = make(map[string]interface{}, len(src.Summary))
		for k, v := range src.Summary {
			cp.Summary[k] = v
		}
	}
	if len(src.Entities) > 0 {
		cp.Entities = append([]string(nil), src.Entities...)
	}
	return &cp
}

func cloneGraph(src *model.AnomalyGraph) *model.AnomalyGraph {
	if src == nil {
		return nil
	}
	result := &model.AnomalyGraph{
		Nodes: make([]*model.BehaviorGraphNode, 0, len(src.Nodes)),
		Edges: make([]*model.BehaviorGraphEdge, 0, len(src.Edges)),
	}
	for _, node := range src.Nodes {
		if node == nil {
			continue
		}
		cp := *node
		if node.Properties != nil {
			cp.Properties = make(map[string]interface{}, len(node.Properties))
			for k, v := range node.Properties {
				cp.Properties[k] = v
			}
		}
		result.Nodes = append(result.Nodes, &cp)
	}
	for _, edge := range src.Edges {
		if edge == nil {
			continue
		}
		cp := *edge
		if edge.Properties != nil {
			cp.Properties = make(map[string]interface{}, len(edge.Properties))
			for k, v := range edge.Properties {
				cp.Properties[k] = v
			}
		}
		result.Edges = append(result.Edges, &cp)
	}
	return result
}
