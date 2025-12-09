package grpcsvc_test

import (
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

	"github.com/m-sec-org/d-eyes/server/internal/api"
	v1 "github.com/m-sec-org/d-eyes/server/internal/api/v1"
	"github.com/m-sec-org/d-eyes/server/internal/config"
	"github.com/m-sec-org/d-eyes/server/internal/grpcsvc"
	"github.com/m-sec-org/d-eyes/server/internal/metrics"
	"github.com/m-sec-org/d-eyes/server/internal/model"
	"github.com/m-sec-org/d-eyes/server/internal/queue/memory"
	"github.com/m-sec-org/d-eyes/server/internal/scheduler"
	"github.com/m-sec-org/d-eyes/server/internal/store"
	pb "github.com/m-sec-org/d-eyes/server/proto/agentservicepb"
)

func TestAgentLifecycleContract(t *testing.T) {
	ctx := context.Background()
	cfg := config.Default()
	cfg.Security.AgentToken = "contract-token"
	cfg.Security.APIKeys = []string{"changeme"}
	cfg.Scheduler.LeaseTTL = time.Minute
	cfg.Scheduler.HeartbeatTimeout = 30 * time.Second

	st := store.NewInMemoryStore()
	queue := memory.New()
	sched := scheduler.New(st, queue, cfg.Scheduler)
	reg := prometheus.NewRegistry()
	m := metrics.New(reg)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	service := grpcsvc.NewService(cfg, st, sched, logger, m, nil, nil, nil, nil, nil)

	registerResp, err := service.Register(ctx, &pb.RegisterRequest{
		Token: cfg.Security.AgentToken,
		Metadata: &pb.AgentMetadata{
			Name:         "agent-contract",
			Platform:     "linux",
			Version:      "1.2.3",
			Capabilities: []string{"respond"},
			Labels: map[string]string{
				"zone": "edge",
			},
		},
	})
	require.NoError(t, err)
	agentID := uuid.MustParse(registerResp.GetAgentId())

	stream := &fakeHeartbeatStream{
		ctx: ctx,
		requests: []*pb.HeartbeatRequest{
			{
				AgentId:   agentID.String(),
				Timestamp: time.Now().Unix(),
				Load:      0.25,
				Telemetry: &pb.HeartbeatTelemetry{
					CpuPercent:    18.5,
					MemoryPercent: 32.0,
				},
				Metadata: map[string]string{
					"telemetry.cpu_percent": "18.5",
					"cache.respond_hits":    "1",
				},
			},
		},
	}
	require.ErrorIs(t, service.Heartbeat(stream), io.EOF)
	require.Len(t, stream.responses, 1)

	agent, err := st.GetAgent(ctx, agentID)
	require.NoError(t, err)
	require.Equal(t, 0.25, agent.Load)
	require.Equal(t, "1", agent.Metadata["cache.respond_hits"])

	task := &model.Task{
		ID:        uuid.New(),
		Type:      model.TaskType("respond"),
		Priority:  1,
		Status:    model.TaskStatusPending,
		Metadata:  map[string]string{"required_capabilities": "respond"},
		Payload:   []byte(`{"flags":{"targets":"/tmp"}}`),
		CreatedBy: "contract-test",
	}
	require.NoError(t, st.CreateTask(ctx, task))
	require.NoError(t, sched.EnqueueTask(ctx, task))

	pullResp, err := service.PullTasks(ctx, &pb.PullTaskRequest{
		AgentId:  agentID.String(),
		MaxTasks: 1,
	})
	require.NoError(t, err)
	require.Len(t, pullResp.Leases, 1)
	lease := pullResp.Leases[0]
	require.Equal(t, task.ID.String(), lease.TaskId)

	summary := []byte(`{"ok":true,"steps":1}`)
	runMetadata := map[string]string{
		"module":                   "respond",
		"telemetry.task_resources": `{"cpu":"5"}`,
	}
	_, err = service.ReportResult(ctx, &pb.ReportResultRequest{
		AgentId:     agentID.String(),
		TaskId:      lease.TaskId,
		LeaseId:     lease.LeaseId,
		Status:      "succeeded",
		SummaryJson: summary,
		Metadata:    runMetadata,
	})
	require.NoError(t, err)

	storedTask, err := st.GetTask(ctx, task.ID)
	require.NoError(t, err)
	require.Equal(t, model.TaskStatusSucceeded, storedTask.Status)
	run, err := st.GetLatestTaskRun(ctx, task.ID)
	require.NoError(t, err)
	require.Equal(t, "respond", run.Metadata["module"])
	require.JSONEq(t, string(summary), string(run.Summary))

	router := newContractRouter(cfg, st, sched)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/tasks/"+task.ID.String(), nil)
	req.Header.Set("X-API-Key", "changeme")
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)
	require.Equal(t, http.StatusOK, resp.Code)

	var body struct {
		ID      string `json:"id"`
		Status  string `json:"status"`
		LastRun *struct {
			Summary  json.RawMessage   `json:"summary"`
			Metadata map[string]string `json:"metadata"`
		} `json:"last_run"`
	}
	require.NoError(t, json.Unmarshal(resp.Body.Bytes(), &body))
	require.Equal(t, task.ID.String(), body.ID)
	require.Equal(t, "succeeded", body.Status)
	require.NotNil(t, body.LastRun)
	require.Contains(t, string(body.LastRun.Summary), `"ok":true`)
	require.Equal(t, "respond", body.LastRun.Metadata["module"])
}

func newContractRouter(cfg config.Config, st store.Store, sched *scheduler.Scheduler) *gin.Engine {
	gin.SetMode(gin.TestMode)
	taskHandler := &v1.TaskHandler{Store: st, Sched: sched}
	reportHandler := &v1.ReportHandler{Store: st}
	return api.NewRouter(
		cfg,
		taskHandler,
		nil,
		&v1.TemplateHandler{},
		reportHandler,
		nil, // catalog
		nil, // plugin
		nil, // bas scenario
		nil, // agent handler
		nil, // audit handler
		nil, // rbac handler
		nil, // artifact handler
		nil, // threat intel
		nil, // behavior
		nil, // compliance
		nil, // playbook
		nil, // cert handler
		nil, // security handler
		nil, // ops handler
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
}
