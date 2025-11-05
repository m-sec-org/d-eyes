package app_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"

	"github.com/m-sec-org/d-eyes/server/internal/api"
	v1 "github.com/m-sec-org/d-eyes/server/internal/api/v1"
	"github.com/m-sec-org/d-eyes/server/internal/config"
	"github.com/m-sec-org/d-eyes/server/internal/grpcsvc"
	"github.com/m-sec-org/d-eyes/server/internal/metrics"
	"github.com/m-sec-org/d-eyes/server/internal/queue/memory"
	"github.com/m-sec-org/d-eyes/server/internal/scheduler"
	"github.com/m-sec-org/d-eyes/server/internal/store"
	pb "github.com/m-sec-org/d-eyes/server/proto/agentservicepb"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

func TestEndToEndTaskFlow(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cfg := config.Default()
	cfg.Security.AgentToken = "integration-token"
	cfg.Security.APIKeys = []string{"integration-key"}
	cfg.Scheduler.LeaseTTL = 30 * time.Second
	cfg.Scheduler.HeartbeatTimeout = 20 * time.Second

	st := store.NewInMemoryStore()
	queue := memory.New()
	sched := scheduler.New(st, queue, cfg.Scheduler)
	reg := prometheus.NewRegistry()
	m := metrics.New(reg)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	taskHandler := &v1.TaskHandler{Store: st, Sched: sched}
	router := api.NewRouter(cfg, taskHandler, nil)
	httpServer := httptest.NewServer(router)
	t.Cleanup(httpServer.Close)

	const bufSize = 1 << 20
	listener := bufconn.Listen(bufSize)
	grpcServer := grpc.NewServer()
	pb.RegisterAgentServiceServer(grpcServer, grpcsvc.NewService(cfg, st, sched, logger, m))
	go func() {
		_ = grpcServer.Serve(listener)
	}()
	t.Cleanup(func() {
		grpcServer.Stop()
		_ = listener.Close()
	})

	conn, err := grpc.DialContext(ctx, "bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return listener.Dial()
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	client := pb.NewAgentServiceClient(conn)

	registerResp, err := client.Register(ctx, &pb.RegisterRequest{
		Token: "integration-token",
		Metadata: &pb.AgentMetadata{
			Name:         "agent-e2e",
			Platform:     "linux",
			Version:      "1.2.3",
			Capabilities: []string{"respond"},
		},
	})
	require.NoError(t, err)

	createReqBody, err := json.Marshal(map[string]any{
		"type":       "respond",
		"priority":   3,
		"payload":    map[string]any{"case": "integration"},
		"created_by": "integration-test",
	})
	require.NoError(t, err)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, httpServer.URL+"/api/v1/tasks", bytes.NewReader(createReqBody))
	require.NoError(t, err)
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("X-API-Key", "integration-key")

	httpResp, err := http.DefaultClient.Do(httpReq)
	require.NoError(t, err)
	require.Equal(t, http.StatusCreated, httpResp.StatusCode)
	defer httpResp.Body.Close()

	var createResp struct {
		ID string `json:"id"`
	}
	require.NoError(t, json.NewDecoder(httpResp.Body).Decode(&createResp))

	pullResp, err := client.PullTasks(ctx, &pb.PullTaskRequest{
		AgentId:  registerResp.AgentId,
		MaxTasks: 1,
	})
	require.NoError(t, err)
	require.Len(t, pullResp.Leases, 1)
	lease := pullResp.Leases[0]
	require.Equal(t, createResp.ID, lease.TaskId)

	_, err = client.ReportResult(ctx, &pb.ReportResultRequest{
		AgentId:     registerResp.AgentId,
		TaskId:      lease.TaskId,
		LeaseId:     lease.LeaseId,
		Status:      "succeeded",
		SummaryJson: []byte(`{"result":"ok"}`),
	})
	require.NoError(t, err)

	getReq, err := http.NewRequestWithContext(ctx, http.MethodGet, httpServer.URL+"/api/v1/tasks/"+createResp.ID, nil)
	require.NoError(t, err)
	getReq.Header.Set("X-API-Key", "integration-key")

	getResp, err := http.DefaultClient.Do(getReq)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, getResp.StatusCode)
	defer getResp.Body.Close()

	var getBody struct {
		Status  string `json:"status"`
		LastRun struct {
			Status  string          `json:"status"`
			Summary json.RawMessage `json:"summary"`
		} `json:"last_run"`
	}
	require.NoError(t, json.NewDecoder(getResp.Body).Decode(&getBody))
	require.Equal(t, "succeeded", getBody.Status)
	require.Equal(t, "succeeded", getBody.LastRun.Status)
	require.JSONEq(t, `{"result":"ok"}`, string(getBody.LastRun.Summary))
}
