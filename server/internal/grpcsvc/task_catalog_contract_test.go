package grpcsvc_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"

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

func TestContract_TaskCatalog_ReportRead_DefaultRequiredCapabilities(t *testing.T) {
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
		{Role: "viewer", Permissions: []string{"tasks.read"}},
	})

	router := newContractRouterWithDeps(cfg, st, sched, catalog, auditMgr, enforcer)

	taskTypes := listTaskTypesViaREST(t, router)
	expectedCaps := requiredCapsFromCatalog(taskTypes, "detect.diag")
	require.NotEmpty(t, expectedCaps)

	taskProfiles := listTaskProfilesViaREST(t, router, "detect.diag")
	require.True(t, len(taskProfiles) > 0, "expected detect.diag profiles")

	payload := map[string]any{"backend": "auto", "rule": ""}
	taskID := createTaskViaREST(t, router, "detect.diag", "detect.diag", payload, nil)

	taskMetadata := getTaskMetadataViaREST(t, router, taskID.String(), "operator")
	require.Equal(t, expectedCaps, taskMetadata["required_capabilities"])

	// Report surface is stable: no runs yet -> 404.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/tasks/"+taskID.String()+"/detect/report", nil)
	req.Header.Set("X-API-Key", "changeme")
	req.Header.Set("X-User-Role", "operator")
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)
	require.Equal(t, http.StatusNotFound, resp.Code, resp.Body.String())

	reg := prometheus.NewRegistry()
	m := metrics.New(reg)
	service := grpcsvc.NewService(cfg, st, sched, logger, m, nil, nil, nil, nil, nil)

	noCapsAgent, err := service.Register(ctx, &pb.RegisterRequest{
		Token: cfg.Security.AgentToken,
		Metadata: &pb.AgentMetadata{
			Name:         "agent-no-detect",
			Platform:     "linux",
			Version:      "1.2.3",
			Capabilities: []string{"audit"},
		},
	})
	require.NoError(t, err)
	noCapsAgentID := uuid.MustParse(noCapsAgent.GetAgentId())

	pullResp, err := service.PullTasks(ctx, &pb.PullTaskRequest{AgentId: noCapsAgentID.String(), MaxTasks: 1})
	require.NoError(t, err)
	require.Empty(t, pullResp.GetLeases(), "agent without detect.diag should not receive task when required_capabilities is injected")

	detectAgent, err := service.Register(ctx, &pb.RegisterRequest{
		Token: cfg.Security.AgentToken,
		Metadata: &pb.AgentMetadata{
			Name:         "agent-detect",
			Platform:     "linux",
			Version:      "1.2.3",
			Capabilities: []string{"detect.diag"},
		},
	})
	require.NoError(t, err)
	detectAgentID := uuid.MustParse(detectAgent.GetAgentId())

	pullResp, err = service.PullTasks(ctx, &pb.PullTaskRequest{AgentId: detectAgentID.String(), MaxTasks: 1})
	require.NoError(t, err)
	require.Len(t, pullResp.GetLeases(), 1)
	lease := pullResp.GetLeases()[0]
	require.Equal(t, taskID.String(), lease.GetTaskId())
	require.Equal(t, "detect.diag", lease.GetTaskType())
	require.Equal(t, "detect.diag", lease.GetProfile())
	assertJSONMapEqual(t, payload, lease.GetPayload())

	exec := model.ExecutionResult{
		Status: "succeeded",
		Summary: model.ExecutionSummary{
			Command:         "detect.diag",
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
	runMeta := map[string]string{"module": "detect.diag"}
	_, err = service.ReportResult(ctx, &pb.ReportResultRequest{
		AgentId:     detectAgentID.String(),
		TaskId:      lease.GetTaskId(),
		LeaseId:     lease.GetLeaseId(),
		Status:      "succeeded",
		SummaryJson: summaryBytes,
		Metadata:    runMeta,
		ExitCode:    0,
	})
	require.NoError(t, err)

	assertTaskReadSurface(t, router, taskID, exec)
	assertTaskReportSurface(t, router, taskID, "detect.diag", "detect.diag", "/api/v1/tasks/%s/detect/report", exec, runMeta)

	req = httptest.NewRequest(http.MethodGet, "/api/v1/tasks/"+taskID.String()+"/detect/report", nil)
	req.Header.Set("X-API-Key", "changeme")
	req.Header.Set("X-User-Role", "viewer")
	resp = httptest.NewRecorder()
	router.ServeHTTP(resp, req)
	require.Equal(t, http.StatusForbidden, resp.Code, resp.Body.String())
}

type contractTaskType struct {
	Name         string   `json:"name"`
	Capabilities []string `json:"capabilities"`
}

type contractTaskProfile struct {
	ID       string `json:"id"`
	TaskType string `json:"task_type"`
}

func listTaskTypesViaREST(t *testing.T, router http.Handler) []contractTaskType {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/task-types", nil)
	req.Header.Set("X-API-Key", "changeme")
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)
	require.Equal(t, http.StatusOK, resp.Code, resp.Body.String())

	var out []contractTaskType
	require.NoError(t, json.Unmarshal(resp.Body.Bytes(), &out))
	return out
}

func listTaskProfilesViaREST(t *testing.T, router http.Handler, taskType string) []contractTaskProfile {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/task-profiles?task_type="+taskType, nil)
	req.Header.Set("X-API-Key", "changeme")
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)
	require.Equal(t, http.StatusOK, resp.Code, resp.Body.String())

	var out []contractTaskProfile
	require.NoError(t, json.Unmarshal(resp.Body.Bytes(), &out))
	return out
}

func requiredCapsFromCatalog(taskTypes []contractTaskType, taskType string) string {
	for _, item := range taskTypes {
		if item.Name != taskType {
			continue
		}
		caps := make([]string, 0, len(item.Capabilities))
		for _, capName := range item.Capabilities {
			capName = strings.TrimSpace(capName)
			if capName != "" {
				caps = append(caps, capName)
			}
		}
		return strings.Join(caps, ",")
	}
	return ""
}

func getTaskMetadataViaREST(t *testing.T, router http.Handler, taskID string, role string) map[string]string {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/tasks/"+taskID, nil)
	req.Header.Set("X-API-Key", "changeme")
	req.Header.Set("X-User-Role", role)
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)
	require.Equal(t, http.StatusOK, resp.Code, resp.Body.String())

	var out struct {
		Metadata map[string]string `json:"metadata"`
	}
	require.NoError(t, json.Unmarshal(resp.Body.Bytes(), &out))
	return out.Metadata
}
