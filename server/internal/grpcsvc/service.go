package grpcsvc

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"

	pb "github.com/m-sec-org/d-eyes/server/proto/agentservicepb"

	"github.com/m-sec-org/d-eyes/server/internal/config"
	"github.com/m-sec-org/d-eyes/server/internal/metrics"
	"github.com/m-sec-org/d-eyes/server/internal/model"
	"github.com/m-sec-org/d-eyes/server/internal/scheduler"
	"github.com/m-sec-org/d-eyes/server/internal/store"
)

// Service implements pb.AgentServiceServer.
type Service struct {
	pb.UnimplementedAgentServiceServer
	store   store.Store
	sched   *scheduler.Scheduler
	cfg     config.Config
	logger  *slog.Logger
	metrics *metrics.Metrics
}

func NewService(cfg config.Config, st store.Store, sched *scheduler.Scheduler, logger *slog.Logger, m *metrics.Metrics) *Service {
	return &Service{store: st, sched: sched, cfg: cfg, logger: logger, metrics: m}
}

func (s *Service) Register(ctx context.Context, req *pb.RegisterRequest) (*pb.RegisterResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("invalid request")
	}
	if req.GetToken() != s.cfg.Security.AgentToken {
		return nil, fmt.Errorf("invalid agent token")
	}
	metadata := req.GetMetadata()
	if metadata == nil {
		return nil, fmt.Errorf("metadata required")
	}
	agent, err := s.store.GetAgentByName(ctx, metadata.GetName())
	if errors.Is(err, store.ErrNotFound) {
		agent = &model.Agent{
			ID:            uuid.New(),
			Name:          metadata.GetName(),
			Platform:      metadata.GetPlatform(),
			Version:       metadata.GetVersion(),
			Capabilities:  append([]string(nil), metadata.GetCapabilities()...),
			Labels:        metadata.GetLabels(),
			Status:        model.AgentStatusOnline,
			LastHeartbeat: time.Now(),
		}
	} else if err != nil {
		return nil, err
	} else {
		agent.Platform = metadata.GetPlatform()
		agent.Version = metadata.GetVersion()
		agent.Capabilities = append([]string(nil), metadata.GetCapabilities()...)
		agent.Labels = metadata.GetLabels()
		agent.Status = model.AgentStatusOnline
		agent.LastHeartbeat = time.Now()
	}
	if err := s.store.UpsertAgent(ctx, agent); err != nil {
		return nil, err
	}
	s.logger.Info("agent registered", "agent_id", agent.ID.String(), "name", agent.Name)
	return &pb.RegisterResponse{
		AgentId:                  agent.ID.String(),
		HeartbeatIntervalSeconds: int64(s.cfg.Scheduler.HeartbeatTimeout / time.Second / 2),
	}, nil
}

func (s *Service) Heartbeat(stream pb.AgentService_HeartbeatServer) error {
	ctx := stream.Context()
	for {
		req, err := stream.Recv()
		if err != nil {
			return err
		}
		agentID, err := uuid.Parse(req.GetAgentId())
		if err != nil {
			s.logger.Warn("invalid agent id in heartbeat", "agent_id", req.GetAgentId(), "error", err)
			continue
		}
		heartbeatTime := time.Unix(req.GetTimestamp(), 0)
		if heartbeatTime.IsZero() {
			heartbeatTime = time.Now()
		}
		if err := s.store.UpdateAgentStatus(ctx, agentID, model.AgentStatusOnline, heartbeatTime, req.GetLoad(), req.GetRunningTasks()); err != nil {
			s.logger.Error("failed to update agent status", "error", err)
			return err
		}
		if err := stream.Send(&pb.HeartbeatResponse{ShouldShutdown: false}); err != nil {
			return err
		}
		if s.metrics != nil {
			s.metrics.Heartbeats.Inc()
		}
	}
}

func (s *Service) PullTasks(ctx context.Context, req *pb.PullTaskRequest) (*pb.PullTaskResponse, error) {
	agentID, err := uuid.Parse(req.GetAgentId())
	if err != nil {
		return nil, fmt.Errorf("invalid agent id: %w", err)
	}
	agent, err := s.store.GetAgent(ctx, agentID)
	if err != nil {
		return nil, err
	}
	var leases []*pb.TaskLease
	max := int(req.GetMaxTasks())
	if max <= 0 {
		max = 1
	}
	for i := 0; i < max; i++ {
		task, run, err := s.sched.LeaseTask(ctx, agent)
		if errors.Is(err, scheduler.ErrNoTaskAvailable) {
			break
		}
		if err != nil {
			return nil, err
		}
		if err := s.sched.MarkRunStarted(ctx, run.LeaseID); err != nil {
			return nil, err
		}
		leases = append(leases, &pb.TaskLease{
			TaskId:              task.ID.String(),
			LeaseId:             run.LeaseID.String(),
			TaskType:            string(task.Type),
			Payload:             append([]byte(nil), task.Payload...),
			LeaseTimeoutSeconds: int64(s.cfg.Scheduler.LeaseTTL / time.Second),
		})
		if s.metrics != nil {
			s.metrics.TasksLeased.Inc()
		}
	}
	return &pb.PullTaskResponse{Leases: leases}, nil
}

func (s *Service) ReportResult(ctx context.Context, req *pb.ReportResultRequest) (*pb.ReportResultResponse, error) {
	leaseID, err := uuid.Parse(req.GetLeaseId())
	if err != nil {
		return nil, fmt.Errorf("invalid lease id: %w", err)
	}
	run, err := s.store.GetTaskRunByLease(ctx, leaseID)
	if err != nil {
		return nil, err
	}
	status := model.TaskStatus(req.GetStatus())
	if status == "" {
		status = model.TaskStatusSucceeded
	}
	if run.Status == model.TaskStatusSucceeded || run.Status == model.TaskStatusFailed || run.Status == model.TaskStatusCanceled {
		return &pb.ReportResultResponse{Accepted: true}, nil
	}
	artifacts := make([]model.Artifact, 0, len(req.GetArtifacts()))
	for _, art := range req.GetArtifacts() {
		artifacts = append(artifacts, model.Artifact{
			ID:        uuid.New(),
			TaskRunID: run.ID,
			Name:      art.GetName(),
			MIMEType:  art.GetContentType(),
			Blob:      append([]byte(nil), art.GetData()...),
		})
	}
	if err := s.sched.CompleteTask(ctx, run.ID, run.TaskID, status, req.GetSummaryJson(), req.GetErrorMessage(), artifacts); err != nil {
		return nil, err
	}
	if s.metrics != nil {
		s.metrics.TasksCompleted.WithLabelValues(string(status)).Inc()
		if run.StartedAt != nil && !run.StartedAt.IsZero() {
			s.metrics.TaskRunDuration.Observe(time.Since(*run.StartedAt).Seconds())
		}
	}
	return &pb.ReportResultResponse{Accepted: true}, nil
}
