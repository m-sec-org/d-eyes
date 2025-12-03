package v1

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/m-sec-org/d-eyes/server/internal/config"
	"github.com/m-sec-org/d-eyes/server/internal/eventing"
	"github.com/m-sec-org/d-eyes/server/internal/model"
	"github.com/m-sec-org/d-eyes/server/internal/store"
)

// EventSink accepts normalized system events.
type EventSink interface {
	Enqueue(ctx context.Context, events []model.SystemEventRecord) error
}

// EventsHandler receives system events from agents and persists them.
type EventsHandler struct {
	Service EventSink
	Store   store.Store
	Config  config.EventsConfig
}

// RegisterRoutes wires the ingestion endpoint.
func (h *EventsHandler) RegisterRoutes(r *gin.RouterGroup) {
	if h == nil {
		return
	}
	r.POST("/events/ingest", h.ingestEvents)
}

type ingestRequest struct {
	AgentID   string        `json:"agent_id"`
	AgentName string        `json:"agent_name"`
	Events    []ingestEvent `json:"events"`
}

type ingestEvent struct {
	Timestamp time.Time         `json:"timestamp"`
	EventType string            `json:"event_type"`
	Source    string            `json:"source"`
	Sequence  uint64            `json:"sequence"`
	Payload   json.RawMessage   `json:"payload"`
	Metadata  map[string]string `json:"metadata"`
	Tags      map[string]string `json:"tags"`
	Raw       json.RawMessage   `json:"raw"`
}

func (h *EventsHandler) ingestEvents(c *gin.Context) {
	if h.Service == nil || !h.Config.Enabled {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "event ingestion disabled"})
		return
	}
	if h.Config.MaxPayloadSize > 0 {
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, h.Config.MaxPayloadSize)
	}
	var req ingestRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid payload", "details": err.Error()})
		return
	}
	if len(req.Events) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "events array must not be empty"})
		return
	}
	if req.AgentID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "agent_id is required"})
		return
	}
	agentID, err := uuid.Parse(req.AgentID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid agent_id"})
		return
	}
	ctx := c.Request.Context()
	var agentName string
	if req.AgentName != "" {
		agentName = req.AgentName
	}
	if h.Store != nil {
		agent, err := h.Store.GetAgent(ctx, agentID)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				c.JSON(http.StatusNotFound, gin.H{"error": "agent not registered"})
				return
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load agent"})
			return
		}
		if agentName == "" {
			agentName = agent.Name
		}
	}
	if agentName == "" {
		agentName = agentID.String()
	}

	now := time.Now().UTC()
	records := make([]model.SystemEventRecord, 0, len(req.Events))
	for idx, evt := range req.Events {
		if evt.EventType == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "event_type is required", "index": idx})
			return
		}
		ts := evt.Timestamp
		if ts.IsZero() {
			ts = now
		}
		metadata := copyStringMap(evt.Metadata)
		tags := copyStringMap(evt.Tags)
		collector := metadata["collector"]
		collectorKind := metadata["collector_kind"]
		records = append(records, model.SystemEventRecord{
			ID:            uuid.New(),
			AgentID:       agentID,
			AgentName:     agentName,
			Collector:     collector,
			CollectorKind: collectorKind,
			EventType:     evt.EventType,
			Source:        evt.Source,
			Timestamp:     ts,
			Sequence:      evt.Sequence,
			Payload:       cloneRaw(evt.Payload),
			Metadata:      metadata,
			Tags:          tags,
			Raw:           cloneRaw(evt.Raw),
			ReceivedAt:    now,
		})
	}

	if err := h.Service.Enqueue(ctx, records); err != nil {
		if errors.Is(err, eventing.ErrBackpressure) {
			c.JSON(http.StatusTooManyRequests, gin.H{"error": "ingest queue saturated, retry later"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to persist events"})
		return
	}
	c.JSON(http.StatusAccepted, gin.H{"count": len(records)})
}

func copyStringMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func cloneRaw(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 {
		return nil
	}
	out := make([]byte, len(raw))
	copy(out, raw)
	return json.RawMessage(out)
}
