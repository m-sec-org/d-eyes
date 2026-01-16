package grpcsvc_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
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

	"github.com/m-sec-org/d-eyes/server/internal/api"
	v1 "github.com/m-sec-org/d-eyes/server/internal/api/v1"
	"github.com/m-sec-org/d-eyes/server/internal/auditlog"
	"github.com/m-sec-org/d-eyes/server/internal/config"
	"github.com/m-sec-org/d-eyes/server/internal/grpcsvc"
	"github.com/m-sec-org/d-eyes/server/internal/metrics"
	"github.com/m-sec-org/d-eyes/server/internal/model"
	"github.com/m-sec-org/d-eyes/server/internal/queue/memory"
	"github.com/m-sec-org/d-eyes/server/internal/rbac"
	"github.com/m-sec-org/d-eyes/server/internal/scheduler"
	"github.com/m-sec-org/d-eyes/server/internal/store"
	"github.com/m-sec-org/d-eyes/server/internal/taskcatalog"
	pb "github.com/m-sec-org/d-eyes/server/proto/agentservicepb"
)

func TestTaskFlowContract_AuditAndDetectDiag(t *testing.T) {
	ctx := context.Background()
	cfg := config.Default()
	cfg.Security.AgentToken = "contract-token"
	cfg.Security.APIKeys = []string{"changeme"}
	cfg.Scheduler.LeaseTTL = time.Minute
	cfg.Scheduler.HeartbeatTimeout = 30 * time.Second

	st := store.NewInMemoryStore()
	queue := memory.New()
	sched := scheduler.New(st, queue, cfg.Scheduler)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	catalog, err := taskcatalog.NewManager(taskcatalog.Config{}, logger)
	require.NoError(t, err)
	_, err = catalog.ImportSeedIfEmpty(ctx, taskcatalog.BuiltInSeed())
	require.NoError(t, err)
	auditMgr, err := auditlog.New("", 0)
	require.NoError(t, err)
	enforcer := rbac.New([]rbac.Policy{
		{Role: "operator", Permissions: []string{"tasks.create", "tasks.read", "reports.view"}},
	})

	router := newContractRouterWithDeps(cfg, st, sched, catalog, auditMgr, enforcer)

	reg := prometheus.NewRegistry()
	m := metrics.New(reg)
	service := grpcsvc.NewService(cfg, st, sched, logger, m, nil, nil, nil, nil, nil)

	registerResp, err := service.Register(ctx, &pb.RegisterRequest{
		Token: cfg.Security.AgentToken,
		Metadata: &pb.AgentMetadata{
			Name:         "agent-contract",
			Platform:     "linux",
			Version:      "1.2.3",
			Capabilities: []string{"audit", "detect.diag"},
		},
	})
	require.NoError(t, err)
	agentID := uuid.MustParse(registerResp.GetAgentId())

	cases := []struct {
		name         string
		taskType     string
		profile      string
		payload      map[string]any
		reportPath   string
		auditSuffix  string
		requiredCaps string
	}{
		{
			name:         "audit",
			taskType:     "audit",
			profile:      "audit",
			payload:      map[string]any{"scope": "system", "targets": "127.0.0.1"},
			reportPath:   "/api/v1/tasks/%s/audit/report",
			auditSuffix:  "audit",
			requiredCaps: "audit",
		},
		{
			name:         "detect.diag",
			taskType:     "detect.diag",
			profile:      "detect.diag",
			payload:      map[string]any{"backend": "auto", "rule": ""},
			reportPath:   "/api/v1/tasks/%s/detect/report",
			auditSuffix:  "detect",
			requiredCaps: "detect.diag",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			taskID := createTaskViaREST(t, router, tc.taskType, tc.profile, tc.payload, map[string]string{
				"required_capabilities": tc.requiredCaps,
			})

			pullResp, err := service.PullTasks(ctx, &pb.PullTaskRequest{
				AgentId:  agentID.String(),
				MaxTasks: 1,
			})
			require.NoError(t, err)
			require.Len(t, pullResp.Leases, 1)
			lease := pullResp.Leases[0]
			require.Equal(t, taskID.String(), lease.GetTaskId())
			require.Equal(t, tc.taskType, lease.GetTaskType())
			require.Equal(t, tc.profile, lease.GetProfile())
			assertJSONMapEqual(t, tc.payload, lease.GetPayload())

			exec := model.ExecutionResult{
				Status: "succeeded",
				Summary: model.ExecutionSummary{
					Command:         tc.taskType,
					Status:          "succeeded",
					DurationSeconds: 0.01,
					Notes:           []string{"contract"},
					Outputs: []model.OutputRecord{
						{Label: "report", Path: "/tmp/contract-report.json"},
					},
				},
				Metadata:   map[string]string{"contract": "true"},
				ExitCode:   0,
				ReportedAt: time.Now().UTC(),
			}
			summaryBytes, err := json.Marshal(exec)
			require.NoError(t, err)

			runMeta := map[string]string{"module": tc.taskType}
			_, err = service.ReportResult(ctx, &pb.ReportResultRequest{
				AgentId:     agentID.String(),
				TaskId:      lease.GetTaskId(),
				LeaseId:     lease.GetLeaseId(),
				Status:      "succeeded",
				SummaryJson: summaryBytes,
				Metadata:    runMeta,
				ExitCode:    0,
			})
			require.NoError(t, err)

			assertTaskReadSurface(t, router, taskID, exec)
			assertTaskReportSurface(t, router, taskID, tc.taskType, tc.profile, tc.reportPath, exec, runMeta)

			events := auditMgr.List(auditlog.Filter{Action: "report.read", Limit: 20})
			found := false
			for _, evt := range events {
				if evt.Resource == "task:"+taskID.String()+"/"+tc.auditSuffix && evt.Result == "success" {
					found = true
					break
				}
			}
			require.True(t, found, "missing audit event report.read for %s", tc.name)
		})
	}
}

func newContractRouterWithDeps(cfg config.Config, st store.Store, sched *scheduler.Scheduler, catalog *taskcatalog.Manager, auditMgr *auditlog.Manager, enforcer *rbac.Enforcer) *gin.Engine {
	gin.SetMode(gin.TestMode)
	taskHandler := &v1.TaskHandler{
		Store:   st,
		Sched:   sched,
		Catalog: catalog,
		Audit:   auditMgr,
		RBAC:    enforcer,
	}
	return api.NewRouter(
		cfg,
		taskHandler,
		nil,
		&v1.TemplateHandler{},
		nil,
		&v1.TaskCatalogHandler{Catalog: catalog},
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
		nil,
		nil,
		nil,
		nil,
		nil,
	)
}

func createTaskViaREST(t *testing.T, router http.Handler, taskType, profile string, payload map[string]any, metadata map[string]string) uuid.UUID {
	t.Helper()
	body := map[string]any{
		"type":     taskType,
		"profile":  profile,
		"payload":  payload,
		"metadata": metadata,
	}
	rawBody, err := json.Marshal(body)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/tasks", bytes.NewReader(rawBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "changeme")
	req.Header.Set("X-User", "contract-user")
	req.Header.Set("X-User-Role", "operator")

	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)
	require.Equal(t, http.StatusCreated, resp.Code, resp.Body.String())

	var out struct {
		ID string `json:"id"`
	}
	require.NoError(t, json.Unmarshal(resp.Body.Bytes(), &out))
	return uuid.MustParse(out.ID)
}

func assertTaskReadSurface(t *testing.T, router http.Handler, taskID uuid.UUID, expected model.ExecutionResult) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/tasks/"+taskID.String(), nil)
	req.Header.Set("X-API-Key", "changeme")
	req.Header.Set("X-User-Role", "operator")
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)
	require.Equal(t, http.StatusOK, resp.Code, resp.Body.String())

	var body struct {
		ID      string `json:"id"`
		Status  string `json:"status"`
		LastRun *struct {
			Summary json.RawMessage `json:"summary"`
		} `json:"last_run"`
	}
	require.NoError(t, json.Unmarshal(resp.Body.Bytes(), &body))
	require.Equal(t, taskID.String(), body.ID)
	require.Equal(t, "succeeded", body.Status)
	require.NotNil(t, body.LastRun)

	var got model.ExecutionResult
	require.NoError(t, json.Unmarshal(body.LastRun.Summary, &got))
	require.Equal(t, expected.Status, got.Status)
	require.Equal(t, expected.Summary.Command, got.Summary.Command)
	require.Equal(t, expected.Metadata["contract"], got.Metadata["contract"])
}

func assertTaskReportSurface(t *testing.T, router http.Handler, taskID uuid.UUID, taskType, profile, pathFmt string, expected model.ExecutionResult, runMeta map[string]string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, formatPath(pathFmt, taskID.String()), nil)
	req.Header.Set("X-API-Key", "changeme")
	req.Header.Set("X-User-Role", "operator")
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)
	require.Equal(t, http.StatusOK, resp.Code, resp.Body.String())

	var body struct {
		TaskID     string                `json:"task_id"`
		TaskType   string                `json:"task_type"`
		Profile    string                `json:"profile"`
		TaskStatus string                `json:"task_status"`
		Result     model.ExecutionResult `json:"result"`
		RunMeta    map[string]string     `json:"run_metadata"`
		ExitCode   int32                 `json:"exit_code"`
		ErrorCode  string                `json:"error_code"`
	}
	require.NoError(t, json.Unmarshal(resp.Body.Bytes(), &body))
	require.Equal(t, taskID.String(), body.TaskID)
	require.Equal(t, taskType, body.TaskType)
	require.Equal(t, profile, body.Profile)
	require.Equal(t, "succeeded", body.TaskStatus)
	require.Equal(t, expected.Status, body.Result.Status)
	require.Equal(t, expected.Metadata["contract"], body.Result.Metadata["contract"])
	require.Equal(t, runMeta["module"], body.RunMeta["module"])
	require.Equal(t, int32(0), body.ExitCode)
	require.Empty(t, body.ErrorCode)
}

func assertJSONMapEqual(t *testing.T, expected map[string]any, payload []byte) {
	t.Helper()
	var got map[string]any
	require.NoError(t, json.Unmarshal(payload, &got))
	require.Equal(t, expected, got)
}

func formatPath(format string, args ...any) string {
	return fmt.Sprintf(format, args...)
}
