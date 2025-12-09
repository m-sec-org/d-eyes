package v1

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

	"github.com/m-sec-org/d-eyes/server/internal/auditlog"
	"github.com/m-sec-org/d-eyes/server/internal/collectorctrl"
	"github.com/m-sec-org/d-eyes/server/internal/config"
	"github.com/m-sec-org/d-eyes/server/internal/model"
	"github.com/m-sec-org/d-eyes/server/internal/rbac"
	"github.com/m-sec-org/d-eyes/server/internal/store"
)

func TestCollectorHandler_ConfigLifecycle(t *testing.T) {
	gin.SetMode(gin.TestMode)
	st := store.NewInMemoryStore()
	auditMgr, err := auditlog.New("", 64)
	require.NoError(t, err)
	enforcer := rbac.New([]rbac.Policy{
		{Role: "operator", Permissions: []string{"collector.config.write", "collector.config.read"}},
	})
	handler := &CollectorHandler{Store: st, RBAC: enforcer, Audit: auditMgr}
	router := gin.New()
	handler.RegisterRoutes(router.Group("/api/v1"))

	agentID := uuid.New()
	payload := map[string]any{
		"agent_id": agentID.String(),
		"config": map[string]any{
			"collectors": []map[string]any{
				{"name": "diag-ebpf", "kind": "ebpf"},
			},
		},
		"updated_by": "tester",
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/collector/configs", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-User", "tester")
	req.Header.Set("X-User-Role", "operator")
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)
	require.Equal(t, http.StatusOK, resp.Code)

	getReq := httptest.NewRequest(http.MethodGet, "/api/v1/collector/configs/"+agentID.String(), nil)
	getResp := httptest.NewRecorder()
	router.ServeHTTP(getResp, getReq)
	require.Equal(t, http.StatusOK, getResp.Code)
	var cfg map[string]any
	require.NoError(t, json.Unmarshal(getResp.Body.Bytes(), &cfg))
	require.EqualValues(t, float64(1), cfg["version"])
}

func TestCollectorHandler_StatusPublishes(t *testing.T) {
	gin.SetMode(gin.TestMode)
	st := store.NewInMemoryStore()
	hub := collectorctrl.NewHub()
	defer hub.Close()
	handler := &CollectorHandler{Store: st, Hub: hub}
	router := gin.New()
	handler.RegisterRoutes(router.Group("/api/v1"))

	streamReq := httptest.NewRequest(http.MethodGet, "/api/v1/collector/status/stream", nil)
	streamResp := httptest.NewRecorder()
	go router.ServeHTTP(streamResp, streamReq)

	agentID := uuid.New()
	body, _ := json.Marshal(map[string]any{
		"agent_id":   agentID.String(),
		"agent_name": "agent-a",
		"version":    2,
		"state":      "running",
		"stats": map[string]any{
			"events_per_sec": 42,
		},
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/collector/status", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)
	require.Equal(t, http.StatusOK, resp.Code)
}

func TestCollectorHandler_ConfigValidationAndRBAC(t *testing.T) {
	gin.SetMode(gin.TestMode)
	t.Run("schema validation", func(t *testing.T) {
		st := store.NewInMemoryStore()
		handler := &CollectorHandler{Store: st}
		router := gin.New()
		handler.RegisterRoutes(router.Group("/api/v1"))
		body := []byte(`{"agent_id":"` + uuid.New().String() + `","config":{"foo":"bar"}}`)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/collector/configs", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		resp := httptest.NewRecorder()
		router.ServeHTTP(resp, req)
		require.Equal(t, http.StatusBadRequest, resp.Code)
	})

	t.Run("rbac enforcement", func(t *testing.T) {
		st := store.NewInMemoryStore()
		enforcer := rbac.New([]rbac.Policy{{Role: "guest", Permissions: []string{}}})
		handler := &CollectorHandler{Store: st, RBAC: enforcer}
		router := gin.New()
		handler.RegisterRoutes(router.Group("/api/v1"))
		valid := []byte(`{"agent_id":"` + uuid.New().String() + `","config":{"collectors":[{"name":"diag","kind":"ebpf"}]}}`)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/collector/configs", bytes.NewReader(valid))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-User-Role", "guest")
		resp := httptest.NewRecorder()
		router.ServeHTTP(resp, req)
		require.Equal(t, http.StatusForbidden, resp.Code)
	})

	t.Run("provider whitelist", func(t *testing.T) {
		st := store.NewInMemoryStore()
		handler := &CollectorHandler{Store: st, AllowedProviders: []string{"kernel"}, AllowedProbes: []string{"diag-ebpf"}}
		router := gin.New()
		handler.RegisterRoutes(router.Group("/api/v1"))
		payload := []byte(`{"agent_id":"` + uuid.New().String() + `","config":{"collectors":[{"name":"diag","kind":"ebpf","providers":["security"],"probes":["diag-ebpf"]}]}}`)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/collector/configs", bytes.NewReader(payload))
		req.Header.Set("Content-Type", "application/json")
		resp := httptest.NewRecorder()
		router.ServeHTTP(resp, req)
		require.Equal(t, http.StatusBadRequest, resp.Code)
	})
}

func TestCollectorHandler_StatusFilters(t *testing.T) {
	gin.SetMode(gin.TestMode)
	st := store.NewInMemoryStore()
	ctx := context.Background()
	require.NoError(t, st.UpsertCollectorStatus(ctx, &model.CollectorStatusSnapshot{
		AgentID:   uuid.New(),
		AgentName: "agent-a",
		State:     "running",
		Stats: map[string]any{
			"drop_rate":  0.5,
			"latency_ms": 600,
		},
		Metadata: map[string]string{"tenant": "acme"},
	}))
	require.NoError(t, st.UpsertCollectorStatus(ctx, &model.CollectorStatusSnapshot{
		AgentID:   uuid.New(),
		AgentName: "agent-b",
		State:     "running",
		Metadata:  map[string]string{"tenant": "beta"},
	}))
	handler := &CollectorHandler{Store: st}
	router := gin.New()
	handler.RegisterRoutes(router.Group("/api/v1"))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/collector/status?tenant=acme", nil)
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)
	require.Equal(t, http.StatusOK, resp.Code)
	var body struct {
		Items []struct {
			AlertLevel string `json:"alert_level"`
			AgentName  string `json:"agent_name"`
		} `json:"items"`
	}
	require.NoError(t, json.Unmarshal(resp.Body.Bytes(), &body))
	require.Len(t, body.Items, 1)
	require.Equal(t, "critical", body.Items[0].AlertLevel)
	require.Equal(t, "agent-a", body.Items[0].AgentName)
}

func TestCollectorHandler_RolloutLifecycle(t *testing.T) {
	gin.SetMode(gin.TestMode)
	st := store.NewInMemoryStore()
	handler := &CollectorHandler{Store: st, Control: config.CollectorControlConfig{RolloutGracePeriod: 2 * time.Minute}}
	router := gin.New()
	handler.RegisterRoutes(router.Group("/api/v1"))
	agentID := uuid.New()
	require.NoError(t, st.UpsertAgent(context.Background(), &model.Agent{ID: agentID, Name: "agent-web", Labels: map[string]string{"role": "web"}}))
	body, _ := json.Marshal(map[string]any{
		"name":     "test-rollout",
		"selector": map[string]any{"role": "web"},
		"config": map[string]any{
			"collectors": []map[string]any{{"name": "diag", "kind": "ebpf"}},
		},
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/collector/configs/rollouts", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)
	require.Equal(t, http.StatusOK, resp.Code)
	var rolloutResp struct {
		Rollout struct {
			ID          string `json:"id"`
			TargetCount int    `json:"target_count"`
		} `json:"rollout"`
	}
	require.NoError(t, json.Unmarshal(resp.Body.Bytes(), &rolloutResp))
	require.Equal(t, 1, rolloutResp.Rollout.TargetCount)
	statusBody, _ := json.Marshal(map[string]any{
		"agent_id":   agentID.String(),
		"agent_name": "agent-web",
		"version":    1,
		"state":      "running",
	})
	statusReq := httptest.NewRequest(http.MethodPost, "/api/v1/collector/status", bytes.NewReader(statusBody))
	statusReq.Header.Set("Content-Type", "application/json")
	statusResp := httptest.NewRecorder()
	router.ServeHTTP(statusResp, statusReq)
	require.Equal(t, http.StatusOK, statusResp.Code)
	getReq := httptest.NewRequest(http.MethodGet, "/api/v1/collector/configs/rollouts/"+rolloutResp.Rollout.ID, nil)
	getResp := httptest.NewRecorder()
	router.ServeHTTP(getResp, getReq)
	require.Equal(t, http.StatusOK, getResp.Code)
	var detail struct {
		Rollout struct {
			AckCount int `json:"ack_count"`
		} `json:"rollout"`
	}
	require.NoError(t, json.Unmarshal(getResp.Body.Bytes(), &detail))
	require.Equal(t, 1, detail.Rollout.AckCount)
}

func TestCollectorHandler_RolloutRollback(t *testing.T) {
	gin.SetMode(gin.TestMode)
	st := store.NewInMemoryStore()
	handler := &CollectorHandler{Store: st}
	router := gin.New()
	handler.RegisterRoutes(router.Group("/api/v1"))
	ctx := context.Background()
	agentID := uuid.New()
	prevConfig, _ := json.Marshal(map[string]any{"collectors": []map[string]any{{"name": "base", "kind": "etw"}}})
	require.NoError(t, st.UpsertAgent(ctx, &model.Agent{ID: agentID, Name: "agent-rollback", Labels: map[string]string{"role": "db"}}))
	require.NoError(t, st.UpsertCollectorConfig(ctx, &model.CollectorConfigSnapshot{AgentID: agentID, Version: 1, Config: prevConfig, UpdatedBy: "tester"}))
	body, _ := json.Marshal(map[string]any{
		"agents": []string{agentID.String()},
		"config": map[string]any{
			"collectors": []map[string]any{{"name": "diag", "kind": "ebpf"}},
		},
	})
	createReq := httptest.NewRequest(http.MethodPost, "/api/v1/collector/configs/rollouts", bytes.NewReader(body))
	createReq.Header.Set("Content-Type", "application/json")
	createResp := httptest.NewRecorder()
	router.ServeHTTP(createResp, createReq)
	require.Equal(t, http.StatusOK, createResp.Code)
	var rollout struct {
		Rollout struct {
			ID string `json:"id"`
		} `json:"rollout"`
	}
	require.NoError(t, json.Unmarshal(createResp.Body.Bytes(), &rollout))
	rollbackReq := httptest.NewRequest(http.MethodPost, "/api/v1/collector/configs/rollouts/"+rollout.Rollout.ID+"/rollback", bytes.NewReader([]byte(`{"reason":"test"}`)))
	rollbackReq.Header.Set("Content-Type", "application/json")
	rollbackResp := httptest.NewRecorder()
	router.ServeHTTP(rollbackResp, rollbackReq)
	require.Equal(t, http.StatusOK, rollbackResp.Code)
	finalCfg, err := st.GetCollectorConfig(ctx, agentID)
	require.NoError(t, err)
	require.Equal(t, int64(1), finalCfg.Version)
	require.JSONEq(t, string(prevConfig), string(finalCfg.Config))
}
