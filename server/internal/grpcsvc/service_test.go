package grpcsvc_test

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"

	"github.com/m-sec-org/d-eyes/server/internal/behavior"
	"github.com/m-sec-org/d-eyes/server/internal/config"
	"github.com/m-sec-org/d-eyes/server/internal/grpcsvc"
	"github.com/m-sec-org/d-eyes/server/internal/metrics"
	"github.com/m-sec-org/d-eyes/server/internal/model"
	"github.com/m-sec-org/d-eyes/server/internal/queue/memory"
	"github.com/m-sec-org/d-eyes/server/internal/scheduler"
	"github.com/m-sec-org/d-eyes/server/internal/store"
	pb "github.com/m-sec-org/d-eyes/server/proto/agentservicepb"

	"google.golang.org/grpc/metadata"
)

func newTestService(t *testing.T) (*grpcsvc.Service, store.Store, *scheduler.Scheduler) {
	return newTestServiceWithRecorder(t, nil)
}

func newTestServiceWithRecorder(t *testing.T, recorder grpcsvc.BehaviorRecorder) (*grpcsvc.Service, store.Store, *scheduler.Scheduler) {
	t.Helper()
	cfg := config.Default()
	cfg.Security.AgentToken = "token"
	cfg.Scheduler.LeaseTTL = time.Minute
	cfg.Scheduler.HeartbeatTimeout = 30 * time.Second

	st := store.NewInMemoryStore()
	queue := memory.New()
	sched := scheduler.New(st, queue, cfg.Scheduler)
	reg := prometheus.NewRegistry()
	m := metrics.New(reg)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := grpcsvc.NewService(cfg, st, sched, logger, m, nil, nil, recorder, nil, nil)
	return svc, st, sched
}

func TestRegisterPullAndReport(t *testing.T) {
	svc, st, sched := newTestService(t)
	ctx := context.Background()

	resp, err := svc.Register(ctx, &pb.RegisterRequest{
		Token: "token",
		Metadata: &pb.AgentMetadata{
			Name:         "agent-1",
			Platform:     "linux",
			Version:      "1.0.0",
			Capabilities: []string{"respond"},
		},
	})
	require.NoError(t, err)
	agentID := uuid.MustParse(resp.AgentId)

	task := &model.Task{
		ID:       uuid.New(),
		Type:     "respond",
		Priority: 1,
		Status:   model.TaskStatusPending,
		Metadata: map[string]string{},
		Payload:  []byte(`{"hello":"world"}`),
	}
	require.NoError(t, st.CreateTask(ctx, task))
	require.NoError(t, sched.EnqueueTask(ctx, task))

	pull, err := svc.PullTasks(ctx, &pb.PullTaskRequest{
		AgentId:  agentID.String(),
		MaxTasks: 1,
	})
	require.NoError(t, err)
	require.Len(t, pull.Leases, 1)
	lease := pull.Leases[0]
	require.Equal(t, task.ID.String(), lease.TaskId)

	_, err = svc.ReportResult(ctx, &pb.ReportResultRequest{
		AgentId:     agentID.String(),
		TaskId:      lease.TaskId,
		LeaseId:     lease.LeaseId,
		Status:      "succeeded",
		SummaryJson: []byte(`{"ok":true}`),
	})
	require.NoError(t, err)

	storedTask, err := st.GetTask(ctx, task.ID)
	require.NoError(t, err)
	require.Equal(t, model.TaskStatusSucceeded, storedTask.Status)

	run, err := st.GetLatestTaskRun(ctx, task.ID)
	require.NoError(t, err)
	require.Equal(t, []byte(`{"ok":true}`), run.Summary)
}

func TestHeartbeatUpdatesAgent(t *testing.T) {
	svc, st, _ := newTestService(t)
	ctx := context.Background()

	agent := &model.Agent{
		ID:            uuid.New(),
		Name:          "agent-heartbeat",
		Status:        model.AgentStatusOnline,
		LastHeartbeat: time.Now().Add(-time.Hour),
	}
	require.NoError(t, st.UpsertAgent(ctx, agent))

	stream := &fakeHeartbeatStream{
		ctx: ctx,
		requests: []*pb.HeartbeatRequest{
			{
				AgentId:   agent.ID.String(),
				Timestamp: time.Now().Unix(),
				Load:      0.3,
			},
		},
	}

	err := svc.Heartbeat(stream)
	require.ErrorIs(t, err, io.EOF)
	require.Len(t, stream.responses, 1)

	updated, err := st.GetAgent(ctx, agent.ID)
	require.NoError(t, err)
	require.WithinDuration(t, time.Now(), updated.LastHeartbeat, time.Second*2)
	require.Equal(t, model.AgentStatusOnline, updated.Status)
}

func TestHeartbeatMetadataForwarded(t *testing.T) {
	recorder := &stubBehaviorRecorder{}
	svc, st, _ := newTestServiceWithRecorder(t, recorder)
	ctx := context.Background()
	agent := &model.Agent{
		ID:            uuid.New(),
		Name:          "agent-meta",
		Status:        model.AgentStatusOnline,
		LastHeartbeat: time.Now().Add(-time.Minute),
	}
	require.NoError(t, st.UpsertAgent(ctx, agent))
	stream := &fakeHeartbeatStream{
		ctx: ctx,
		requests: []*pb.HeartbeatRequest{
			{
				AgentId:   agent.ID.String(),
				Timestamp: time.Now().Unix(),
				Load:      1.0,
				Telemetry: &pb.HeartbeatTelemetry{},
				Metadata: map[string]string{
					"telemetry.cpu_percent": "42.0",
					"cache.respond_hits":    "7",
				},
			},
		},
	}
	require.ErrorIs(t, svc.Heartbeat(stream), io.EOF)
	require.Len(t, recorder.heartbeats, 1)
	metric := recorder.heartbeats[0]
	require.Equal(t, "42.0", metric.Metadata["telemetry.cpu_percent"])
	require.Equal(t, "7", metric.Metadata["cache.respond_hits"])

	stored, err := st.GetAgent(ctx, agent.ID)
	require.NoError(t, err)
	require.Equal(t, "7", stored.Metadata["cache.respond_hits"])
}

type stubBehaviorRecorder struct {
	heartbeats []behavior.HeartbeatMetric
}

func (s *stubBehaviorRecorder) RecordHeartbeat(_ context.Context, metric behavior.HeartbeatMetric) {
	s.heartbeats = append(s.heartbeats, metric)
}

func (s *stubBehaviorRecorder) RecordTaskTelemetry(_ context.Context, payload behavior.TaskTelemetry) {
}

func TestHeartbeatShouldShutdownFromLabels(t *testing.T) {
	svc, st, _ := newTestService(t)
	ctx := context.Background()
	agent := &model.Agent{
		ID:     uuid.New(),
		Name:   "agent-drain",
		Labels: map[string]string{"agent.desired_state": "shutdown"},
		Status: model.AgentStatusOnline,
	}
	require.NoError(t, st.UpsertAgent(ctx, agent))

	stream := &fakeHeartbeatStream{
		ctx: ctx,
		requests: []*pb.HeartbeatRequest{
			{
				AgentId:   agent.ID.String(),
				Timestamp: time.Now().Unix(),
				Load:      0.1,
				Telemetry: &pb.HeartbeatTelemetry{},
			},
		},
	}
	err := svc.Heartbeat(stream)
	require.ErrorIs(t, err, io.EOF)
	require.Len(t, stream.responses, 1)
	require.True(t, stream.responses[0].GetShouldShutdown())
}

type fakeHeartbeatStream struct {
	ctx       context.Context
	requests  []*pb.HeartbeatRequest
	responses []*pb.HeartbeatResponse
}

func (f *fakeHeartbeatStream) Send(resp *pb.HeartbeatResponse) error {
	f.responses = append(f.responses, resp)
	return nil
}

func (f *fakeHeartbeatStream) Recv() (*pb.HeartbeatRequest, error) {
	if len(f.requests) == 0 {
		return nil, io.EOF
	}
	req := f.requests[0]
	f.requests = f.requests[1:]
	if len(f.requests) == 0 {
		// next call will signal EOF
	}
	return req, nil
}

func (f *fakeHeartbeatStream) SetHeader(metadata.MD) error  { return nil }
func (f *fakeHeartbeatStream) SendHeader(metadata.MD) error { return nil }
func (f *fakeHeartbeatStream) SetTrailer(metadata.MD)       {}
func (f *fakeHeartbeatStream) Context() context.Context     { return f.ctx }
func (f *fakeHeartbeatStream) SendMsg(m interface{}) error  { return nil }
func (f *fakeHeartbeatStream) RecvMsg(m interface{}) error  { return nil }
