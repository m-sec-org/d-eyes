package v1_test

import (
	"bytes"
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
	"github.com/m-sec-org/d-eyes/server/internal/queue/memory"
	"github.com/m-sec-org/d-eyes/server/internal/scheduler"
	"github.com/m-sec-org/d-eyes/server/internal/store"
)

func setupTestRouter(t *testing.T) (*gin.Engine, store.Store, *scheduler.Scheduler) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	st := store.NewInMemoryStore()
	queue := memory.New()
	cfg := config.Config{
		Security: config.SecurityConfig{
			APIKeys: []string{"changeme"},
		},
		Scheduler: config.SchedulerConfig{
			LeaseTTL:          2 * time.Minute,
			MaxRetries:        3,
			HeartbeatTimeout:  30 * time.Second,
			QueueCapacity:     128,
			LeasePollInterval: time.Millisecond,
		},
	}
	sched := scheduler.New(st, queue, cfg.Scheduler)
	handler := &v1.TaskHandler{Store: st, Sched: sched}
	router := api.NewRouter(cfg, handler, nil)
	return router, st, sched
}

func performRequest(r http.Handler, req *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func TestTaskLifecycle(t *testing.T) {
	router, st, sched := setupTestRouter(t)
	ctx := context.Background()

	payload := map[string]any{"targets": []string{"/tmp"}}
	body, _ := json.Marshal(map[string]any{
		"type":       "respond",
		"priority":   2,
		"payload":    payload,
		"metadata":   map[string]string{"required_capabilities": "respond"},
		"created_by": "tester",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/tasks", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "changeme")
	resp := performRequest(router, req)
	require.Equal(t, http.StatusCreated, resp.Code)

	var created map[string]string
	require.NoError(t, json.Unmarshal(resp.Body.Bytes(), &created))
	taskID := uuid.MustParse(created["id"])

	task, err := st.GetTask(ctx, taskID)
	require.NoError(t, err)
	require.Equal(t, model.TaskStatusPending, task.Status)

	runAgent := &model.Agent{
		ID:            uuid.New(),
		Name:          "agent-1",
		Capabilities:  []string{"respond"},
		Status:        model.AgentStatusOnline,
		LastHeartbeat: time.Now(),
	}
	require.NoError(t, st.UpsertAgent(ctx, runAgent))
	require.NoError(t, sched.PrimeFromStore(ctx))

	leasedTask, run, err := sched.LeaseTask(ctx, runAgent)
	require.NoError(t, err)
	require.Equal(t, taskID, leasedTask.ID)
	require.NoError(t, sched.MarkRunStarted(ctx, run.LeaseID))
	require.NoError(t, sched.CompleteTask(ctx, run.ID, run.TaskID, model.TaskStatusSucceeded, []byte(`{"ok":true}`), "", nil))

	getReq := httptest.NewRequest(http.MethodGet, "/api/v1/tasks/"+taskID.String(), nil)
	getReq.Header.Set("X-API-Key", "changeme")
	getResp := performRequest(router, getReq)
	require.Equal(t, http.StatusOK, getResp.Code)

	var getBody v1TaskResponse
	require.NoError(t, json.Unmarshal(getResp.Body.Bytes(), &getBody))
	require.Equal(t, "succeeded", getBody.Status)
	require.NotNil(t, getBody.LastRun)
	require.Equal(t, "succeeded", getBody.LastRun.Status)

	listReq := httptest.NewRequest(http.MethodGet, "/api/v1/tasks?status=succeeded", nil)
	listReq.Header.Set("X-API-Key", "changeme")
	listResp := performRequest(router, listReq)
	require.Equal(t, http.StatusOK, listResp.Code)

	var listBody []v1TaskResponse
	require.NoError(t, json.Unmarshal(listResp.Body.Bytes(), &listBody))
	require.Len(t, listBody, 1)
	require.Equal(t, "succeeded", listBody[0].Status)

	retryReq := httptest.NewRequest(http.MethodPost, "/api/v1/tasks/"+taskID.String()+"/retry", nil)
	retryReq.Header.Set("X-API-Key", "changeme")
	retryResp := performRequest(router, retryReq)
	require.Equal(t, http.StatusAccepted, retryResp.Code)

	var retryBody v1TaskResponse
	require.NoError(t, json.Unmarshal(retryResp.Body.Bytes(), &retryBody))
	require.Equal(t, 1, retryBody.RetryCount)
	require.Equal(t, "pending", retryBody.Status)
}

type v1TaskResponse struct {
	ID         string           `json:"id"`
	Status     string           `json:"status"`
	LastRun    *v1TaskRunOutput `json:"last_run"`
	RetryCount int              `json:"retry_count"`
}

type v1TaskRunOutput struct {
	Status string `json:"status"`
}
