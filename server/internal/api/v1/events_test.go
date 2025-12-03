package v1

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"

	"github.com/m-sec-org/d-eyes/server/internal/config"
	"github.com/m-sec-org/d-eyes/server/internal/eventing"
	"github.com/m-sec-org/d-eyes/server/internal/metrics"
	"github.com/m-sec-org/d-eyes/server/internal/model"
	"github.com/m-sec-org/d-eyes/server/internal/store"
)

func TestEventsHandlerIngestSuccess(t *testing.T) {
	gin.SetMode(gin.TestMode)
	st := store.NewInMemoryStore()
	agent := &model.Agent{ID: uuid.New(), Name: "agent-one"}
	require.NoError(t, st.UpsertAgent(context.Background(), agent))

	cfg := config.EventsConfig{
		Enabled:        true,
		QueueCapacity:  16,
		MaxBatch:       4,
		FlushInterval:  10 * time.Millisecond,
		MaxPayloadSize: 1024 * 1024,
	}
	metricsCollector := metrics.New(prometheus.NewRegistry())
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := eventing.NewService(cfg, st, metricsCollector, log)
	require.NotNil(t, svc)
	t.Cleanup(func() { svc.Close() })

	handler := &EventsHandler{
		Service: svc,
		Store:   st,
		Config:  cfg,
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

func TestEventsHandlerBackpressure(t *testing.T) {
	gin.SetMode(gin.TestMode)
	st := store.NewInMemoryStore()
	agent := &model.Agent{ID: uuid.New(), Name: "agent-two"}
	require.NoError(t, st.UpsertAgent(context.Background(), agent))

	handler := &EventsHandler{
		Service: failingSink{err: eventing.ErrBackpressure},
		Store:   st,
		Config: config.EventsConfig{
			Enabled:        true,
			MaxPayloadSize: 1024 * 1024,
		},
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
	handler := &EventsHandler{
		Service: nil,
		Store:   st,
		Config: config.EventsConfig{
			Enabled:        false,
			MaxPayloadSize: 1024,
		},
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

func (f failingSink) Enqueue(context.Context, []model.SystemEventRecord) error {
	return f.err
}
