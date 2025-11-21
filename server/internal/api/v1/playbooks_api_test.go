package v1_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	v1 "github.com/m-sec-org/d-eyes/server/internal/api/v1"
	"github.com/m-sec-org/d-eyes/server/internal/model"
	"github.com/m-sec-org/d-eyes/server/internal/playbook"
	"github.com/m-sec-org/d-eyes/server/internal/security"
	"github.com/m-sec-org/d-eyes/server/internal/store"
)

func setupPlaybookRouter(t *testing.T, role string, engine *playbook.Engine) (*gin.Engine, *playbook.Manager) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	st := store.NewInMemoryStore()
	mgr := playbook.NewManager(st, nil)
	handler := &v1.PlaybookHandler{Manager: mgr, Engine: engine}
	router := gin.New()
	router.Use(func(c *gin.Context) {
		security.WithPrincipal(c, security.Principal{User: "tester", Role: role})
	})
	api := router.Group("/api/v1")
	handler.RegisterRoutes(api)
	return router, mgr
}

func createPlaybook(t *testing.T, mgr *playbook.Manager, name string) *model.Playbook {
	t.Helper()
	ctx := context.Background()
	pb := &model.Playbook{
		Name:    name,
		Trigger: model.PlaybookTrigger{Type: "manual"},
		Actions: []model.PlaybookAction{
			{Type: "task.dispatch", TaskType: "respond"},
		},
	}
	require.NoError(t, mgr.Create(ctx, pb))
	return pb
}

func TestPlaybookRunRequiresEngine(t *testing.T) {
	router, _ := setupPlaybookRouter(t, "operator", nil)
	id := uuid.New()
	body, _ := json.Marshal(map[string]any{"type": "manual"})
	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/v1/playbooks/%s/run", id), bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp := performRequest(router, req)
	require.Equal(t, http.StatusServiceUnavailable, resp.Code)
}

func TestPlaybookRunRequiresActiveStatus(t *testing.T) {
	router, mgr := setupPlaybookRouter(t, "operator", &playbook.Engine{})
	pb := createPlaybook(t, mgr, "containment")

	body, _ := json.Marshal(map[string]any{"type": "manual"})
	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/v1/playbooks/%s/run", pb.ID), bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp := performRequest(router, req)
	require.Equal(t, http.StatusBadRequest, resp.Code)
	require.Contains(t, resp.Body.String(), "not active")
}

func TestPlaybookApprovalValidatesRequestBody(t *testing.T) {
	router, mgr := setupPlaybookRouter(t, "operator", &playbook.Engine{})
	pb := createPlaybook(t, mgr, "approval-check")

	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/v1/playbooks/%s/approvals", pb.ID), bytes.NewReader([]byte(`{"action":"approve"}`)))
	req.Header.Set("Content-Type", "application/json")

	resp := performRequest(router, req)
	require.Equal(t, http.StatusBadRequest, resp.Code)
	require.Contains(t, resp.Body.String(), "Role")
}
