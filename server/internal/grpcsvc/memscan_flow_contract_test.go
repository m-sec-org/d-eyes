package grpcsvc_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
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

func TestTaskFlowContract_DetectMemscan_WindowsCapabilityGate(t *testing.T) {
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

	linuxLikeAgent, err := service.Register(ctx, &pb.RegisterRequest{
		Token: cfg.Security.AgentToken,
		Metadata: &pb.AgentMetadata{
			Name:         "agent-linux-like",
			Platform:     "linux",
			Version:      "1.2.3",
			Capabilities: []string{"detect.diag"},
		},
	})
	require.NoError(t, err)
	linuxAgentID := uuid.MustParse(linuxLikeAgent.GetAgentId())

	windowsOptInAgent, err := service.Register(ctx, &pb.RegisterRequest{
		Token: cfg.Security.AgentToken,
		Metadata: &pb.AgentMetadata{
			Name:         "agent-windows-opt-in",
			Platform:     "windows",
			Version:      "1.2.3",
			Capabilities: []string{"detect.memscan"},
		},
	})
	require.NoError(t, err)
	windowsAgentID := uuid.MustParse(windowsOptInAgent.GetAgentId())

	payload := map[string]any{
		"pid":         float64(1),
		"backend":     "auto",
		"rule":        "",
		"rwx_only":    true,
		"max_bytes":   float64(33554432),
		"max_regions": float64(128),
		"evidence":    false,
		"minidump":    false,
	}
	taskID := createTaskViaREST(t, router, "detect.memscan", "detect.memscan", payload, map[string]string{
		"required_capabilities":     "detect.memscan",
		"memscan_approval_required": "true",
		"memscan_approved":          "true",
	})

	pullResp, err := service.PullTasks(ctx, &pb.PullTaskRequest{
		AgentId:  linuxAgentID.String(),
		MaxTasks: 1,
	})
	require.NoError(t, err)
	require.Empty(t, pullResp.GetLeases(), "non-windows agent should not receive detect.memscan when required_capabilities is set")

	pullResp, err = service.PullTasks(ctx, &pb.PullTaskRequest{
		AgentId:  windowsAgentID.String(),
		MaxTasks: 1,
	})
	require.NoError(t, err)
	require.Len(t, pullResp.GetLeases(), 1)
	lease := pullResp.GetLeases()[0]
	require.Equal(t, taskID.String(), lease.GetTaskId())
	require.Equal(t, "detect.memscan", lease.GetTaskType())
	require.Equal(t, "detect.memscan", lease.GetProfile())
	assertJSONMapEqual(t, payload, lease.GetPayload())

	exec := model.ExecutionResult{
		Status: "succeeded",
		Summary: model.ExecutionSummary{
			Command:         "detect.memscan",
			Status:          "succeeded",
			DurationSeconds: 0.01,
			Notes:           []string{"contract"},
			Outputs: []model.OutputRecord{
				{
					Label: "内存扫描报告",
					Path:  `C:\d-eyes\reports\detect\memscan\contract-memscan-pid-1.json`,
				},
			},
		},
		Metadata:   map[string]string{"contract": "true"},
		ExitCode:   0,
		ReportedAt: time.Now().UTC(),
	}
	summaryBytes, err := json.Marshal(exec)
	require.NoError(t, err)
	runMeta := map[string]string{"module": "detect.memscan"}
	_, err = service.ReportResult(ctx, &pb.ReportResultRequest{
		AgentId:     windowsAgentID.String(),
		TaskId:      lease.GetTaskId(),
		LeaseId:     lease.GetLeaseId(),
		Status:      "succeeded",
		SummaryJson: summaryBytes,
		Metadata:    runMeta,
		ExitCode:    0,
	})
	require.NoError(t, err)

	assertTaskReadSurface(t, router, taskID, exec)
	assertTaskReportSurface(t, router, taskID, "detect.memscan", "detect.memscan", "/api/v1/tasks/%s/detect/report", exec, runMeta)

	events := auditMgr.List(auditlog.Filter{Action: "report.read", Limit: 50})
	found := false
	for _, evt := range events {
		if evt.Resource == "task:"+taskID.String()+"/detect" && evt.Result == "success" {
			found = true
			break
		}
	}
	require.True(t, found, "missing audit event report.read for detect.memscan")
}
