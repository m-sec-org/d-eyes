package v1_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/m-sec-org/d-eyes/server/internal/api"
	v1 "github.com/m-sec-org/d-eyes/server/internal/api/v1"
	"github.com/m-sec-org/d-eyes/server/internal/config"
	"github.com/m-sec-org/d-eyes/server/internal/model"
	queueMemory "github.com/m-sec-org/d-eyes/server/internal/queue/memory"
	"github.com/m-sec-org/d-eyes/server/internal/scheduler"
	"github.com/m-sec-org/d-eyes/server/internal/store"
)

func TestQueueSummary(t *testing.T) {
	gin.SetMode(gin.TestMode)
	st := store.NewInMemoryStore()
	q := queueMemory.New()
	cfg := config.SchedulerConfig{
		LeaseTTL:          time.Minute,
		MaxRetries:        1,
		HeartbeatTimeout:  time.Minute,
		QueueCapacity:     10,
		LeasePollInterval: time.Millisecond,
	}
	sched := scheduler.New(st, q, cfg)
	task := &model.Task{ID: uuid.New(), Type: model.TaskType("respond")}
	require.NoError(t, q.Push(context.Background(), task))
	sched.RecordNewTask(model.TaskStatusPending)

	queueHandler := &v1.QueueHandler{Scheduler: sched}
	router := api.NewRouter(
		config.Config{},
		nil,
		nil,
		nil,
		nil,
		nil,
		nil,
		nil,
		nil,
		nil,
		nil,
		nil,
		nil,
		nil,
		nil,
		nil,
		nil,
		nil,
		nil,
		queueHandler,
		nil, // collector handler
		nil, // events handler
		nil, // mfa store
		nil, // metrics handler
		nil, // task stream
		nil, // queue stream
		nil, // detection stream
		nil, // threat stream
		nil, // anomaly stream
	)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/queues/summary", nil)
	req.Header.Set("X-User", "tester")
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)
	require.Equal(t, http.StatusOK, resp.Code)

	var body struct {
		QueueDepth    float64                `json:"queue_depth"`
		BASQueueDepth float64                `json:"bas_queue_depth"`
		InFlight      float64                `json:"in_flight"`
		StatusCounts  map[string]interface{} `json:"status_counts"`
	}
	require.NoError(t, json.Unmarshal(resp.Body.Bytes(), &body))
	require.GreaterOrEqual(t, body.QueueDepth, 1.0)
	require.NotNil(t, body.StatusCounts)
	require.Contains(t, body.StatusCounts, "pending")
}
