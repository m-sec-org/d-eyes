package v1

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/require"

	"github.com/m-sec-org/d-eyes/server/internal/config"
	"github.com/m-sec-org/d-eyes/server/internal/eventing"
	"github.com/m-sec-org/d-eyes/server/internal/metrics"
	"github.com/m-sec-org/d-eyes/server/internal/model"
	"github.com/m-sec-org/d-eyes/server/internal/rbac"
	"github.com/m-sec-org/d-eyes/server/internal/security"
	"github.com/m-sec-org/d-eyes/server/internal/store"
)

func TestEventsHandlerIngestSuccess(t *testing.T) {
	gin.SetMode(gin.TestMode)
	st := store.NewInMemoryStore()
	agent := &model.Agent{ID: uuid.New(), Name: "agent-one"}
	require.NoError(t, st.UpsertAgent(context.Background(), agent))

	cfg := config.EventsConfig{
		Enabled:         true,
		QueueCapacity:   16,
		MaxBatch:        4,
		FlushInterval:   10 * time.Millisecond,
		MaxPayloadSize:  1024 * 1024,
		DefaultPriority: "normal",
		PriorityQueues: map[string]config.EventPriorityQueueConfig{
			"normal": {QueueCapacity: 16, MaxBatch: 4},
		},
	}
	metricsCollector := metrics.New(prometheus.NewRegistry())
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := eventing.NewService(cfg, st, metricsCollector, log)
	require.NotNil(t, svc)
	t.Cleanup(func() { svc.Close() })
	parserRegistry, err := eventing.NewParserRegistry(cfg, metricsCollector, log)
	require.NoError(t, err)

	handler := &EventsHandler{
		Service: svc,
		Store:   st,
		Config:  cfg,
		Parsers: parserRegistry,
		Metrics: metricsCollector,
	}

	router := gin.New()
	apiGroup := router.Group("/api/v1")
	handler.RegisterRoutes(apiGroup)

	body := map[string]any{
		"agent_id": agent.ID.String(),
		"events": []map[string]any{
			{
				"event_type": "process.exec",
				"source":     "ebpf",
				"metadata": map[string]string{
					"collector":      "diag-ebpf",
					"collector_kind": "ebpf",
				},
				"payload": map[string]any{"pid": 1234},
			},
		},
	}
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/events/ingest", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()

	router.ServeHTTP(resp, req)
	require.Equal(t, http.StatusAccepted, resp.Code)

	count, err := st.CountSystemEvents(context.Background(), time.Time{})
	require.NoError(t, err)
	require.EqualValues(t, 1, count)
}

func TestEventsHandlerRejectsEventFailingParserValidation(t *testing.T) {
	gin.SetMode(gin.TestMode)
	st := store.NewInMemoryStore()
	agent := &model.Agent{ID: uuid.New(), Name: "agent-parser"}
	require.NoError(t, st.UpsertAgent(context.Background(), agent))

	cfg := config.EventsConfig{
		Enabled:         true,
		QueueCapacity:   8,
		MaxBatch:        4,
		FlushInterval:   5 * time.Millisecond,
		MaxPayloadSize:  1024 * 1024,
		DefaultPriority: "normal",
		PriorityQueues: map[string]config.EventPriorityQueueConfig{
			"normal": {QueueCapacity: 8, MaxBatch: 4},
		},
		Parsers: []config.EventParserConfig{
			{
				Name:             "require-collector",
				Enabled:          true,
				EventTypes:       []string{"process.exec"},
				RequiredMetadata: []string{"collector"},
			},
		},
	}
	metricsCollector := metrics.New(prometheus.NewRegistry())
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := eventing.NewService(cfg, st, metricsCollector, log)
	require.NotNil(t, svc)
	t.Cleanup(func() { svc.Close() })
	parserRegistry, err := eventing.NewParserRegistry(cfg, metricsCollector, log)
	require.NoError(t, err)

	handler := &EventsHandler{
		Service: svc,
		Store:   st,
		Config:  cfg,
		Parsers: parserRegistry,
		Metrics: metricsCollector,
	}

	router := gin.New()
	apiGroup := router.Group("/api/v1")
	handler.RegisterRoutes(apiGroup)

	body := map[string]any{
		"agent_id": agent.ID.String(),
		"events": []map[string]any{
			{
				"event_type": "process.exec",
				"source":     "ebpf",
				"payload":    map[string]any{"pid": 1234},
			},
		},
	}
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/events/ingest", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()

	router.ServeHTTP(resp, req)
	require.Equal(t, http.StatusBadRequest, resp.Code)
	var details map[string]any
	require.NoError(t, json.Unmarshal(resp.Body.Bytes(), &details))
	require.Equal(t, "event validation failed", details["error"])

	count, err := st.CountSystemEvents(context.Background(), time.Time{})
	require.NoError(t, err)
	require.EqualValues(t, 0, count)
	require.Equal(t, 1.0, readCounterValue(t, metricsCollector.SystemEventsDropped))
}

func TestEventsHandlerBackpressure(t *testing.T) {
	gin.SetMode(gin.TestMode)
	st := store.NewInMemoryStore()
	agent := &model.Agent{ID: uuid.New(), Name: "agent-two"}
	require.NoError(t, st.UpsertAgent(context.Background(), agent))

	parserRegistry, err := eventing.NewParserRegistry(config.EventsConfig{}, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	require.NoError(t, err)
	handler := &EventsHandler{
		Service: failingSink{err: eventing.ErrBackpressure},
		Store:   st,
		Config: config.EventsConfig{
			Enabled:        true,
			MaxPayloadSize: 1024 * 1024,
		},
		Parsers: parserRegistry,
	}
	router := gin.New()
	handler.RegisterRoutes(router.Group("/api/v1"))

	body, _ := json.Marshal(map[string]any{
		"agent_id": agent.ID.String(),
		"events": []map[string]any{
			{"event_type": "file.create"},
		},
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/events/ingest", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)
	require.Equal(t, http.StatusTooManyRequests, resp.Code)
}

func TestEventsHandlerDisabled(t *testing.T) {
	gin.SetMode(gin.TestMode)
	st := store.NewInMemoryStore()
	parserRegistry, err := eventing.NewParserRegistry(config.EventsConfig{}, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	require.NoError(t, err)
	handler := &EventsHandler{
		Service: nil,
		Store:   st,
		Config: config.EventsConfig{
			Enabled:        false,
			MaxPayloadSize: 1024,
		},
		Parsers: parserRegistry,
	}
	router := gin.New()
	handler.RegisterRoutes(router.Group("/api/v1"))

	body, _ := json.Marshal(map[string]any{
		"agent_id": uuid.New().String(),
		"events": []map[string]any{
			{"event_type": "noop"},
		},
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/events/ingest", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)
	require.Equal(t, http.StatusServiceUnavailable, resp.Code)
}

type failingSink struct {
	err error
}

func (f failingSink) Enqueue(context.Context, string, []model.SystemEventRecord) error {
	return f.err
}

func TestEventsHandlerListEventsFiltersPriority(t *testing.T) {
	gin.SetMode(gin.TestMode)
	st := store.NewInMemoryStore()
	agentID := uuid.New()
	received := time.Now().UTC()
	events := []model.SystemEventRecord{
		{ID: uuid.New(), AgentID: agentID, AgentName: "a", EventType: "process.exec", Source: "ebpf", Priority: "high", StorageTier: "hot", ReceivedAt: received},
		{ID: uuid.New(), AgentID: agentID, AgentName: "a", EventType: "fs.open", Source: "ebpf", Priority: "low", StorageTier: "warm", ReceivedAt: received.Add(-time.Minute)},
	}
	require.NoError(t, st.InsertSystemEvents(context.Background(), events))
	handler := &EventsHandler{
		Store:  st,
		Config: config.EventsConfig{Enabled: true},
		RBAC:   rbac.New([]rbac.Policy{{Role: "operator", Permissions: []string{"events.read"}}}),
	}
	router := gin.New()
	router.Use(func(c *gin.Context) {
		security.WithPrincipal(c, security.Principal{User: "alice", Role: "operator"})
		c.Next()
	})
	api := router.Group("/api/v1")
	handler.RegisterRoutes(api)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/events?priority=high", nil)
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)
	require.Equal(t, http.StatusOK, resp.Code)
	var body struct {
		Items []model.SystemEventRecord `json:"items"`
	}
	require.NoError(t, json.Unmarshal(resp.Body.Bytes(), &body))
	require.Len(t, body.Items, 1)
	require.Equal(t, "high", body.Items[0].Priority)
}

func TestEventsHandlerListDetectionEvents(t *testing.T) {
	gin.SetMode(gin.TestMode)
	st := store.NewInMemoryStore()
	now := time.Now().UTC()
	records := []model.SystemEventRecord{
		{ID: uuid.New(), EventType: "detection.alert", Source: "server", Priority: "high", StorageTier: "hot", ReceivedAt: now},
		{ID: uuid.New(), EventType: "process.exec", Source: "ebpf", Priority: "normal", StorageTier: "hot", ReceivedAt: now.Add(-time.Minute)},
	}
	require.NoError(t, st.InsertSystemEvents(context.Background(), records))
	handler := &EventsHandler{
		Store:  st,
		Config: config.EventsConfig{Enabled: true},
		RBAC:   rbac.New([]rbac.Policy{{Role: "operator", Permissions: []string{"events.read"}}}),
	}
	router := gin.New()
	router.Use(func(c *gin.Context) {
		security.WithPrincipal(c, security.Principal{User: "alice", Role: "operator"})
		c.Next()
	})
	api := router.Group("/api/v1")
	handler.RegisterRoutes(api)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/events/detections", nil)
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)
	require.Equal(t, http.StatusOK, resp.Code)
	var body struct {
		Items []model.SystemEventRecord `json:"items"`
	}
	require.NoError(t, json.Unmarshal(resp.Body.Bytes(), &body))
	require.Len(t, body.Items, 1)
	require.Equal(t, "detection.alert", body.Items[0].EventType)
}

func TestEventsHandlerListEventsPaginationAndCursor(t *testing.T) {
	gin.SetMode(gin.TestMode)
	st := store.NewInMemoryStore()
	agentID := uuid.New()
	base := time.Now().UTC()
	events := []model.SystemEventRecord{
		{ID: uuid.New(), AgentID: agentID, AgentName: "agent", EventType: "process.exec", Source: "ebpf", Priority: "normal", StorageTier: "hot", ReceivedAt: base.Add(-2 * time.Minute)},
		{ID: uuid.New(), AgentID: agentID, AgentName: "agent", EventType: "fs.open", Source: "ebpf", Priority: "normal", StorageTier: "hot", ReceivedAt: base.Add(-time.Minute)},
		{ID: uuid.New(), AgentID: agentID, AgentName: "agent", EventType: "net.connect", Source: "ebpf", Priority: "normal", StorageTier: "hot", ReceivedAt: base},
	}
	require.NoError(t, st.InsertSystemEvents(context.Background(), events))
	handler := &EventsHandler{
		Store:  st,
		Config: config.EventsConfig{Enabled: true},
		RBAC:   rbac.New([]rbac.Policy{{Role: "operator", Permissions: []string{"events.read"}}}),
	}
	router := gin.New()
	router.Use(func(c *gin.Context) {
		security.WithPrincipal(c, security.Principal{User: "alice", Role: "operator"})
		c.Next()
	})
	api := router.Group("/api/v1")
	handler.RegisterRoutes(api)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/events?limit=2", nil)
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)
	require.Equal(t, http.StatusOK, resp.Code)
	var page1 struct {
		Items      []model.SystemEventRecord `json:"items"`
		NextCursor *eventCursor              `json:"next_cursor"`
	}
	require.NoError(t, json.Unmarshal(resp.Body.Bytes(), &page1))
	require.Len(t, page1.Items, 2)
	require.NotNil(t, page1.NextCursor)
	require.Equal(t, events[2].ID, page1.Items[0].ID)
	require.Equal(t, events[1].ID, page1.Items[1].ID)

	cursor := page1.NextCursor
	query := fmt.Sprintf("/api/v1/events?limit=2&cursor_time=%s&cursor_id=%s",
		url.QueryEscape(cursor.ReceivedAt.Format(time.RFC3339Nano)),
		cursor.ID.String(),
	)
	req2 := httptest.NewRequest(http.MethodGet, query, nil)
	resp2 := httptest.NewRecorder()
	router.ServeHTTP(resp2, req2)
	require.Equal(t, http.StatusOK, resp2.Code)
	var page2 struct {
		Items      []model.SystemEventRecord `json:"items"`
		NextCursor *eventCursor              `json:"next_cursor"`
	}
	require.NoError(t, json.Unmarshal(resp2.Body.Bytes(), &page2))
	require.Len(t, page2.Items, 1)
	require.Nil(t, page2.NextCursor)
	require.Equal(t, events[0].ID, page2.Items[0].ID)

	reqAsc := httptest.NewRequest(http.MethodGet, "/api/v1/events?limit=3&sort=asc", nil)
	respAsc := httptest.NewRecorder()
	router.ServeHTTP(respAsc, reqAsc)
	require.Equal(t, http.StatusOK, respAsc.Code)
	var ascBody struct {
		Items []model.SystemEventRecord `json:"items"`
	}
	require.NoError(t, json.Unmarshal(respAsc.Body.Bytes(), &ascBody))
	require.Len(t, ascBody.Items, 3)
	require.Equal(t, events[0].ID, ascBody.Items[0].ID)
	require.Equal(t, events[2].ID, ascBody.Items[2].ID)
}

func TestEventsHandlerEventStats(t *testing.T) {
	gin.SetMode(gin.TestMode)
	st := store.NewInMemoryStore()
	agentID := uuid.New()
	now := time.Now().UTC()
	events := []model.SystemEventRecord{
		{ID: uuid.New(), AgentID: agentID, AgentName: "a", EventType: "process.exec", Source: "ebpf", Priority: "high", StorageTier: "hot", ReceivedAt: now},
		{ID: uuid.New(), AgentID: agentID, AgentName: "a", EventType: "fs.open", Source: "etw", Priority: "low", StorageTier: "warm", ReceivedAt: now.Add(time.Minute)},
		{ID: uuid.New(), AgentID: agentID, AgentName: "a", EventType: "process.exec", Source: "ebpf", Priority: "high", StorageTier: "hot", ReceivedAt: now.Add(2 * time.Minute)},
	}
	require.NoError(t, st.InsertSystemEvents(context.Background(), events))
	handler := &EventsHandler{
		Store:  st,
		Config: config.EventsConfig{Enabled: true},
		RBAC:   rbac.New([]rbac.Policy{{Role: "operator", Permissions: []string{"events.read"}}}),
	}
	router := gin.New()
	router.Use(func(c *gin.Context) {
		security.WithPrincipal(c, security.Principal{User: "bob", Role: "operator"})
		c.Next()
	})
	api := router.Group("/api/v1")
	handler.RegisterRoutes(api)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/events/stats?source=ebpf", nil)
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)
	require.Equal(t, http.StatusOK, resp.Code)
	var stats store.SystemEventAggregates
	require.NoError(t, json.Unmarshal(resp.Body.Bytes(), &stats))
	require.EqualValues(t, 2, stats.Total)
	require.EqualValues(t, 2, stats.ByEventType["process.exec"])
	require.EqualValues(t, 2, stats.BySource["ebpf"])
}

func TestEventsHandlerAppliesRetentionMetadata(t *testing.T) {
	gin.SetMode(gin.TestMode)
	st := store.NewInMemoryStore()
	agent := &model.Agent{ID: uuid.New(), Name: "agent-retention"}
	require.NoError(t, st.UpsertAgent(context.Background(), agent))

	cfg := config.EventsConfig{
		Enabled:         true,
		QueueCapacity:   8,
		MaxBatch:        4,
		FlushInterval:   5 * time.Millisecond,
		MaxPayloadSize:  1024 * 1024,
		DefaultPriority: "normal",
		PriorityQueues: map[string]config.EventPriorityQueueConfig{
			"normal": {QueueCapacity: 8, MaxBatch: 4},
		},
		Retention: config.EventRetentionConfig{
			Hot:  5 * time.Minute,
			Warm: 15 * time.Minute,
			Cold: 30 * time.Minute,
		},
	}
	metricsCollector := metrics.New(prometheus.NewRegistry())
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := eventing.NewService(cfg, st, metricsCollector, log)
	require.NotNil(t, svc)
	t.Cleanup(func() { svc.Close() })
	parserRegistry, err := eventing.NewParserRegistry(cfg, metricsCollector, log)
	require.NoError(t, err)

	handler := &EventsHandler{
		Service: svc,
		Store:   st,
		Config:  cfg,
		Parsers: parserRegistry,
		Metrics: metricsCollector,
	}

	router := gin.New()
	apiGroup := router.Group("/api/v1")
	handler.RegisterRoutes(apiGroup)

	body := map[string]any{
		"agent_id": agent.ID.String(),
		"events": []map[string]any{
			{
				"event_type": "process.exec",
				"metadata": map[string]string{
					"collector": "diag-ebpf",
				},
			},
		},
	}
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/events/ingest", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()

	router.ServeHTTP(resp, req)
	require.Equal(t, http.StatusAccepted, resp.Code)

	var stored []model.SystemEventRecord
	require.Eventually(t, func() bool {
		results, err := st.QuerySystemEvents(context.Background(), store.SystemEventQuery{Limit: 10})
		require.NoError(t, err)
		if len(results) == 0 {
			return false
		}
		stored = results
		return true
	}, time.Second, 10*time.Millisecond)
	require.Len(t, stored, 1)
	meta := stored[0].Metadata
	require.NotNil(t, meta)
	require.Equal(t, "hot", meta["storage_tier"])
	hotUntil, err := time.Parse(time.RFC3339Nano, meta["retention.hot_until"])
	require.NoError(t, err)
	warmUntil, err := time.Parse(time.RFC3339Nano, meta["retention.warm_until"])
	require.NoError(t, err)
	coldUntil, err := time.Parse(time.RFC3339Nano, meta["retention.cold_until"])
	require.NoError(t, err)
	require.True(t, hotUntil.Before(warmUntil) || hotUntil.Equal(warmUntil))
	require.True(t, warmUntil.Before(coldUntil) || warmUntil.Equal(coldUntil))
}

func TestEventsIngestToQueryIntegration(t *testing.T) {
	gin.SetMode(gin.TestMode)
	st := store.NewInMemoryStore()
	agent := &model.Agent{ID: uuid.New(), Name: "agent-end-to-end"}
	require.NoError(t, st.UpsertAgent(context.Background(), agent))

	cfg := config.EventsConfig{
		Enabled:         true,
		QueueCapacity:   8,
		MaxBatch:        4,
		FlushInterval:   5 * time.Millisecond,
		MaxPayloadSize:  1024 * 1024,
		DefaultPriority: "high",
		PriorityQueues: map[string]config.EventPriorityQueueConfig{
			"high": {QueueCapacity: 8, MaxBatch: 4},
		},
		Retention: config.EventRetentionConfig{
			Hot:  2 * time.Minute,
			Warm: 3 * time.Minute,
			Cold: 10 * time.Minute,
		},
		Parsers: []config.EventParserConfig{
			{
				Name:             "process-schema",
				Enabled:          true,
				EventTypes:       []string{"process.exec"},
				RequiredMetadata: []string{"collector"},
			},
		},
	}
	metricsCollector := metrics.New(prometheus.NewRegistry())
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := eventing.NewService(cfg, st, metricsCollector, log)
	require.NotNil(t, svc)
	t.Cleanup(func() { svc.Close() })
	parserRegistry, err := eventing.NewParserRegistry(cfg, metricsCollector, log)
	require.NoError(t, err)

	handler := &EventsHandler{
		Service: svc,
		Store:   st,
		Config:  cfg,
		RBAC: rbac.New([]rbac.Policy{
			{Role: "operator", Permissions: []string{"events.read"}},
		}),
		Parsers: parserRegistry,
		Metrics: metricsCollector,
	}

	router := gin.New()
	router.Use(func(c *gin.Context) {
		security.WithPrincipal(c, security.Principal{User: "alice", Role: "operator"})
		c.Next()
	})
	apiGroup := router.Group("/api/v1")
	handler.RegisterRoutes(apiGroup)

	body := map[string]any{
		"agent_id": agent.ID.String(),
		"events": []map[string]any{
			{
				"event_type": "process.exec",
				"metadata": map[string]string{
					"collector": "diag-ebpf",
				},
				"storage_tier": "warm",
				"priority":     "high",
			},
		},
	}
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/events/ingest", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)
	require.Equal(t, http.StatusAccepted, resp.Code)

	require.Eventually(t, func() bool {
		count, err := st.CountSystemEvents(context.Background(), time.Time{})
		require.NoError(t, err)
		return count == 1
	}, time.Second, 10*time.Millisecond)

	listReq := httptest.NewRequest(http.MethodGet, "/api/v1/events?storage_tier=warm", nil)
	listResp := httptest.NewRecorder()
	router.ServeHTTP(listResp, listReq)
	require.Equal(t, http.StatusOK, listResp.Code)
	var bodyResp struct {
		Items []model.SystemEventRecord `json:"items"`
	}
	require.NoError(t, json.Unmarshal(listResp.Body.Bytes(), &bodyResp))
	require.Len(t, bodyResp.Items, 1)
	item := bodyResp.Items[0]
	require.Equal(t, "warm", item.StorageTier)
	require.Equal(t, "high", item.Priority)
	require.NotNil(t, item.Metadata)
	require.Equal(t, "warm", item.Metadata["storage_tier"])
	require.NotEmpty(t, item.Metadata["retention.hot_until"])
	require.NotEmpty(t, item.Metadata["retention.warm_until"])
	require.NotEmpty(t, item.Metadata["retention.cold_until"])
}

func readCounterValue(t *testing.T, counter prometheus.Counter) float64 {
	t.Helper()
	var metric dto.Metric
	require.NoError(t, counter.Write(&metric))
	return metric.GetCounter().GetValue()
}
