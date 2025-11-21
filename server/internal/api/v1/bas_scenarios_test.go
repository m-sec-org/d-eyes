package v1_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	v1 "github.com/m-sec-org/d-eyes/server/internal/api/v1"
	"github.com/m-sec-org/d-eyes/server/internal/auditlog"
	"github.com/m-sec-org/d-eyes/server/internal/basscenarios"
	"github.com/m-sec-org/d-eyes/server/internal/rbac"
	"github.com/m-sec-org/d-eyes/server/internal/security"
	"github.com/m-sec-org/d-eyes/server/internal/store"
)

func setupBASScenarioRouter(t *testing.T, role string, policies []rbac.Policy) (*gin.Engine, *basscenarios.Manager, *auditlog.Manager) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	st := store.NewInMemoryStore()
	mgr, err := basscenarios.NewManager(basscenarios.Config{
		Store: st,
		DefaultApprovalPolicy: []basscenarios.ApprovalRule{
			{Role: "secops"},
			{Role: "ciso"},
		},
	}, nil)
	require.NoError(t, err)
	auditMgr, err := auditlog.New("", 64)
	require.NoError(t, err)
	handler := &v1.BASScenarioHandler{
		Manager: mgr,
		RBAC:    rbac.New(policies),
		Audit:   auditMgr,
	}
	router := gin.New()
	router.Use(func(c *gin.Context) {
		security.WithPrincipal(c, security.Principal{User: "tester", Role: role})
	})
	api := router.Group("/api/v1")
	handler.RegisterRoutes(api)
	return router, mgr, auditMgr
}

func TestBASScenarioHandlerCreateRequiresPermission(t *testing.T) {
	router, _, _ := setupBASScenarioRouter(t, "auditor", []rbac.Policy{
		{Role: "auditor", Permissions: []string{"bas.view"}},
	})
	body := map[string]any{
		"name":              "Unauthorized",
		"requires_approval": true,
		"steps": []map[string]any{
			{"id": "s1", "name": "Recon", "action": "noop"},
		},
	}
	data, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/bas-scenarios", bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")

	resp := performRequest(router, req)
	require.Equal(t, http.StatusForbidden, resp.Code)
}

func TestBASScenarioHandlerCreateAndListApprovals(t *testing.T) {
	router, mgr, _ := setupBASScenarioRouter(t, "bas-admin", []rbac.Policy{
		{Role: "bas-admin", Permissions: []string{"bas.manage", "bas.view", "bas.approve"}},
	})
	id := createScenarioViaAPI(t, router, "/api/v1/bas-scenarios")

	// Ensure scenario persisted.
	stored, err := mgr.Get(context.Background(), id)
	require.NoError(t, err)
	require.Equal(t, "draft", stored.Status)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/bas-scenarios/"+id.String()+"/approvals", nil)
	resp := performRequest(router, req)
	require.Equal(t, http.StatusOK, resp.Code)

	var payload map[string]any
	require.NoError(t, json.Unmarshal(resp.Body.Bytes(), &payload))
	require.Contains(t, payload, "approval_policy")
	require.Contains(t, payload, "approval_records")
}

func TestBASScenarioHandlerApprovalEndpoint(t *testing.T) {
	router, _, auditMgr := setupBASScenarioRouter(t, "bas-admin", []rbac.Policy{
		{Role: "bas-admin", Permissions: []string{"bas.manage", "bas.view", "bas.approve"}},
	})
	id := createScenarioViaAPI(t, router, "/api/v1/bas-scenarios")

	publishBody, _ := json.Marshal(map[string]string{"updated_by": "author"})
	publishReq := httptest.NewRequest(http.MethodPost, "/api/v1/bas-scenarios/"+id.String()+"/publish", bytes.NewReader(publishBody))
	publishReq.Header.Set("Content-Type", "application/json")
	require.Equal(t, http.StatusOK, performRequest(router, publishReq).Code)

	approve := func(role, actor string) *httptest.ResponseRecorder {
		body, _ := json.Marshal(map[string]string{
			"role":  role,
			"actor": actor,
			"notes": "ok",
		})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/bas-scenarios/"+id.String()+"/approvals", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		return performRequest(router, req)
	}

	first := approve("secops", "secops-user")
	require.Equal(t, http.StatusOK, first.Code)
	var firstScenario basscenarios.Scenario
	require.NoError(t, json.Unmarshal(first.Body.Bytes(), &firstScenario))
	require.Equal(t, basscenarios.StatusPending.String(), firstScenario.Status)
	require.Equal(t, basscenarios.ScenarioApprovalApproved, firstScenario.ApprovalRecords[0].Status)

	second := approve("ciso", "ciso-user")
	require.Equal(t, http.StatusOK, second.Code)
	var finalScenario basscenarios.Scenario
	require.NoError(t, json.Unmarshal(second.Body.Bytes(), &finalScenario))
	require.Equal(t, basscenarios.StatusApproved.String(), finalScenario.Status)
	require.Equal(t, basscenarios.ScenarioApprovalApproved, finalScenario.ApprovalRecords[1].Status)

	events := auditMgr.List(auditlog.Filter{Action: "bas.scenario"})
	require.NotEmpty(t, events)
}

func createScenarioViaAPI(t *testing.T, router http.Handler, path string) uuid.UUID {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"name":              "Red Team",
		"description":       "baseline",
		"requires_approval": true,
		"steps": []map[string]any{
			{"id": "s1", "name": "Recon", "action": "noop"},
		},
	})
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp := performRequest(router, req)
	require.Equal(t, http.StatusCreated, resp.Code)

	var created basscenarios.Scenario
	require.NoError(t, json.Unmarshal(resp.Body.Bytes(), &created))
	require.NotEqual(t, uuid.Nil, created.ID)
	return created.ID
}
