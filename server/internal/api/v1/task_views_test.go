package v1_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"

	"github.com/m-sec-org/d-eyes/server/internal/api"
	v1 "github.com/m-sec-org/d-eyes/server/internal/api/v1"
	"github.com/m-sec-org/d-eyes/server/internal/config"
	"github.com/m-sec-org/d-eyes/server/internal/store"
)

func TestTaskViewCRUD(t *testing.T) {
	gin.SetMode(gin.TestMode)
	st := store.NewInMemoryStore()
	taskHandler := &v1.TaskHandler{Store: st}
	taskViewHandler := &v1.TaskViewHandler{Store: st}
	router := api.NewRouter(
		config.Config{},
		taskHandler,
		taskViewHandler,
		nil, // template
		nil, // report
		nil, // catalog
		nil, // plugin
		nil, // bas
		nil, // agent
		nil, // audit
		nil, // rbac
		nil, // artifact
		nil, // threat intel
		nil, // behavior
		nil, // compliance
		nil, // playbook
		nil, // cert
		nil, // security
		nil, // ops
		nil, // queue handler
		nil, // collector handler
		nil, // events handler
		nil, // mfa
		nil, // metrics
		nil, // task stream
		nil, // queue stream
		nil, // detection stream
		nil, // threat stream
		nil, // anomaly stream
	)

	body := bytes.NewBufferString(`{"name":"活跃任务","filters":{"status":["running"]},"page_size":75}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/task-views", body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-User", "tester")
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)
	require.Equal(t, http.StatusCreated, resp.Code)

	var created map[string]any
	require.NoError(t, json.Unmarshal(resp.Body.Bytes(), &created))
	id := created["id"].(string)

	listReq := httptest.NewRequest(http.MethodGet, "/api/v1/task-views", nil)
	listReq.Header.Set("X-User", "tester")
	listResp := httptest.NewRecorder()
	router.ServeHTTP(listResp, listReq)
	require.Equal(t, http.StatusOK, listResp.Code)

	var listBody struct {
		Views []map[string]any `json:"views"`
	}
	require.NoError(t, json.Unmarshal(listResp.Body.Bytes(), &listBody))
	require.Len(t, listBody.Views, 1)
	require.Equal(t, "活跃任务", listBody.Views[0]["name"])

	updatePayload := bytes.NewBufferString(`{"name":"队列视图","filters":{"status":["pending","running"]},"page_size":120}`)
	updateReq := httptest.NewRequest(http.MethodPut, "/api/v1/task-views/"+id, updatePayload)
	updateReq.Header.Set("Content-Type", "application/json")
	updateReq.Header.Set("X-User", "tester")
	updateResp := httptest.NewRecorder()
	router.ServeHTTP(updateResp, updateReq)
	require.Equal(t, http.StatusOK, updateResp.Code)

	deleteReq := httptest.NewRequest(http.MethodDelete, "/api/v1/task-views/"+id, nil)
	deleteReq.Header.Set("X-User", "tester")
	deleteResp := httptest.NewRecorder()
	router.ServeHTTP(deleteResp, deleteReq)
	require.Equal(t, http.StatusNoContent, deleteResp.Code)
}
