package v1

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/m-sec-org/d-eyes/server/internal/config"
	"github.com/m-sec-org/d-eyes/server/internal/eventing"
	"github.com/m-sec-org/d-eyes/server/internal/metrics"
	"github.com/m-sec-org/d-eyes/server/internal/model"
	"github.com/m-sec-org/d-eyes/server/internal/rbac"
	"github.com/m-sec-org/d-eyes/server/internal/security"
	"github.com/m-sec-org/d-eyes/server/internal/store"
)

// EventSink accepts normalized system events.
type EventSink interface {
	Enqueue(ctx context.Context, priority string, events []model.SystemEventRecord) error
}

// EventsHandler receives system events from agents and persists them.
type EventsHandler struct {
	Service EventSink
	Store   store.Store
	Config  config.EventsConfig
	RBAC    *rbac.Enforcer
	Parsers *eventing.ParserRegistry
	Metrics *metrics.Metrics
}

// RegisterRoutes wires the ingestion endpoint.
func (h *EventsHandler) RegisterRoutes(r *gin.RouterGroup) {
	if h == nil {
		return
	}
	r.POST("/events/ingest", h.ingestEvents)
	r.GET("/events", h.listEvents)
	r.GET("/events/stats", h.eventStats)
	r.GET("/events/detections", h.listDetectionEvents)
}

type ingestRequest struct {
	AgentID   string        `json:"agent_id"`
	AgentName string        `json:"agent_name"`
	Events    []ingestEvent `json:"events"`
}

type ingestEvent struct {
	Timestamp   time.Time         `json:"timestamp"`
	EventType   string            `json:"event_type"`
	Source      string            `json:"source"`
	Sequence    uint64            `json:"sequence"`
	Payload     json.RawMessage   `json:"payload"`
	Metadata    map[string]string `json:"metadata"`
	Tags        map[string]string `json:"tags"`
	Raw         json.RawMessage   `json:"raw"`
	Priority    string            `json:"priority"`
	StorageTier string            `json:"storage_tier"`
}

type eventCursor struct {
	ReceivedAt time.Time `json:"received_at"`
	ID         uuid.UUID `json:"id"`
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
	grouped := make(map[string][]model.SystemEventRecord)
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
		priority := h.normalizePriority(evt.Priority)
		tier := normalizeStorageTier(evt.StorageTier)
		grouped[priority] = append(grouped[priority], model.SystemEventRecord{
			ID:            uuid.New(),
			AgentID:       agentID,
			AgentName:     agentName,
			Collector:     collector,
			CollectorKind: collectorKind,
			EventType:     evt.EventType,
			Source:        evt.Source,
			Priority:      priority,
			StorageTier:   tier,
			Timestamp:     ts,
			Sequence:      evt.Sequence,
			Payload:       cloneRaw(evt.Payload),
			Metadata:      metadata,
			Tags:          tags,
			Raw:           cloneRaw(evt.Raw),
			ReceivedAt:    now,
		})
		record := &grouped[priority][len(grouped[priority])-1]
		if err := h.applyParsers(record); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "event validation failed", "details": err.Error(), "index": idx})
			return
		}
	}
	total := 0
	for priority, records := range grouped {
		total += len(records)
		if err := h.Service.Enqueue(ctx, priority, records); err != nil {
			if errors.Is(err, eventing.ErrBackpressure) {
				c.JSON(http.StatusTooManyRequests, gin.H{"error": "ingest queue saturated, retry later", "priority": priority})
				return
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to persist events"})
			return
		}
	}
	c.JSON(http.StatusAccepted, gin.H{"count": total})
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

func (h *EventsHandler) normalizePriority(p string) string {
	name := strings.ToLower(strings.TrimSpace(p))
	if strings.TrimSpace(name) == "" {
		name = strings.ToLower(strings.TrimSpace(h.Config.DefaultPriority))
	}
	if name == "" {
		name = "normal"
	}
	if len(h.Config.PriorityQueues) == 0 {
		return name
	}
	if _, ok := h.Config.PriorityQueues[name]; ok {
		return name
	}
	defaultLane := strings.ToLower(strings.TrimSpace(h.Config.DefaultPriority))
	if _, ok := h.Config.PriorityQueues[defaultLane]; ok && defaultLane != "" {
		return defaultLane
	}
	return name
}

func normalizeStorageTier(tier string) string {
	switch strings.ToLower(strings.TrimSpace(tier)) {
	case "warm":
		return "warm"
	case "cold":
		return "cold"
	default:
		return "hot"
	}
}

func (h *EventsHandler) listEvents(c *gin.Context) {
	if !h.authorizeEventsRead(c) {
		return
	}
	if h.Store == nil {
		c.JSON(http.StatusNotImplemented, gin.H{"error": "store unavailable"})
		return
	}
	query, err := h.buildEventQuery(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	requestedLimit := store.ClampEventQueryLimit(query.Limit)
	fetchLimit := store.ClampEventQueryLimit(requestedLimit + 1)
	query.Limit = fetchLimit
	events, err := h.Store.QuerySystemEvents(c.Request.Context(), query)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to query events"})
		return
	}
	rawCount := len(events)
	if rawCount > requestedLimit {
		events = events[:requestedLimit]
	}
	hasMore := rawCount == fetchLimit && len(events) > 0
	resp := gin.H{"items": events}
	if hasMore {
		last := events[len(events)-1]
		resp["next_cursor"] = &eventCursor{
			ReceivedAt: last.ReceivedAt,
			ID:         last.ID,
		}
	}
	c.JSON(http.StatusOK, resp)
}

func (h *EventsHandler) listDetectionEvents(c *gin.Context) {
	if !h.authorizeEventsRead(c) {
		return
	}
	if h.Store == nil {
		c.JSON(http.StatusNotImplemented, gin.H{"error": "store unavailable"})
		return
	}
	query, err := h.buildEventQuery(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	query.EventType = "detection.alert"
	requestedLimit := store.ClampEventQueryLimit(query.Limit)
	fetchLimit := store.ClampEventQueryLimit(requestedLimit + 1)
	query.Limit = fetchLimit
	events, err := h.Store.QuerySystemEvents(c.Request.Context(), query)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to query events"})
		return
	}
	rawCount := len(events)
	if rawCount > requestedLimit {
		events = events[:requestedLimit]
	}
	hasMore := rawCount == fetchLimit && len(events) > 0
	resp := gin.H{"items": events}
	if hasMore {
		last := events[len(events)-1]
		resp["next_cursor"] = &eventCursor{
			ReceivedAt: last.ReceivedAt,
			ID:         last.ID,
		}
	}
	c.JSON(http.StatusOK, resp)
}

func (h *EventsHandler) eventStats(c *gin.Context) {
	if !h.authorizeEventsRead(c) {
		return
	}
	if h.Store == nil {
		c.JSON(http.StatusNotImplemented, gin.H{"error": "store unavailable"})
		return
	}
	query, err := h.buildEventQuery(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	stats, err := h.Store.AggregateSystemEvents(c.Request.Context(), query)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to query aggregates"})
		return
	}
	c.JSON(http.StatusOK, stats)
}

func (h *EventsHandler) authorizeEventsRead(c *gin.Context) bool {
	if h == nil || h.RBAC == nil {
		return true
	}
	principal := security.PrincipalFrom(c)
	if h.RBAC.Enforce(principal.Role, "events.read") {
		return true
	}
	c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
	return false
}

func (h *EventsHandler) buildEventQuery(c *gin.Context) (store.SystemEventQuery, error) {
	var query store.SystemEventQuery
	if agent := strings.TrimSpace(c.Query("agent_id")); agent != "" {
		id, err := uuid.Parse(agent)
		if err != nil {
			return query, fmt.Errorf("invalid agent_id")
		}
		query.AgentID = id
	}
	query.Collector = strings.TrimSpace(c.Query("collector"))
	query.CollectorKind = strings.TrimSpace(c.Query("collector_kind"))
	query.EventType = strings.TrimSpace(c.Query("event_type"))
	query.Source = strings.TrimSpace(c.Query("source"))
	query.Priorities = parseListQuery(c, "priority")
	query.StorageTiers = parseListQuery(c, "storage_tier")
	if since := strings.TrimSpace(c.Query("since")); since != "" {
		parsed, err := parseTimestamp(since)
		if err != nil {
			return query, fmt.Errorf("invalid since")
		}
		query.Since = parsed
	}
	if until := strings.TrimSpace(c.Query("until")); until != "" {
		parsed, err := parseTimestamp(until)
		if err != nil {
			return query, fmt.Errorf("invalid until")
		}
		query.Until = parsed
	}
	if limitParam := strings.TrimSpace(c.Query("limit")); limitParam != "" {
		limit, err := strconv.Atoi(limitParam)
		if err != nil {
			return query, fmt.Errorf("invalid limit")
		}
		query.Limit = limit
	}
	switch strings.ToLower(strings.TrimSpace(c.Query("sort"))) {
	case "", "desc":
		query.SortAscending = false
	case "asc":
		query.SortAscending = true
	default:
		return query, fmt.Errorf("invalid sort")
	}
	cursorTime := strings.TrimSpace(c.Query("cursor_time"))
	cursorID := strings.TrimSpace(c.Query("cursor_id"))
	if cursorTime != "" || cursorID != "" {
		if cursorTime == "" || cursorID == "" {
			return query, fmt.Errorf("cursor_time and cursor_id are required together")
		}
		ts, err := parseTimestamp(cursorTime)
		if err != nil {
			return query, fmt.Errorf("invalid cursor_time")
		}
		id, err := uuid.Parse(cursorID)
		if err != nil {
			return query, fmt.Errorf("invalid cursor_id")
		}
		query.CursorReceivedAt = ts
		query.CursorID = id
	}
	return query, nil
}

func parseListQuery(c *gin.Context, key string) []string {
	values := c.QueryArray(key)
	if len(values) == 0 {
		if raw := strings.TrimSpace(c.Query(key)); raw != "" {
			values = strings.Split(raw, ",")
		}
	}
	for i, v := range values {
		values[i] = strings.TrimSpace(v)
	}
	return values
}

func parseTimestamp(value string) (time.Time, error) {
	if value == "" {
		return time.Time{}, nil
	}
	if ts, err := time.Parse(time.RFC3339Nano, value); err == nil {
		return ts, nil
	}
	return time.Parse(time.RFC3339, value)
}

func (h *EventsHandler) applyParsers(rec *model.SystemEventRecord) error {
	if rec.Metadata == nil {
		rec.Metadata = make(map[string]string)
	}
	if rec.Tags == nil {
		rec.Tags = make(map[string]string)
	}
	rec.Metadata["storage_tier"] = rec.StorageTier
	if h.Parsers != nil {
		if err := h.Parsers.Normalize(rec); err != nil {
			h.recordParserDrop(1)
			return err
		}
	}
	eventing.ApplyRetentionMetadata(h.Config.Retention, rec)
	return nil
}

func (h *EventsHandler) recordParserDrop(count int) {
	if h == nil || h.Metrics == nil || count <= 0 {
		return
	}
	h.Metrics.SystemEventsDropped.Add(float64(count))
}
