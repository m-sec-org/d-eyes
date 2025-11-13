package grpcsvc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"

	pb "github.com/m-sec-org/d-eyes/server/proto/agentservicepb"

	"github.com/m-sec-org/d-eyes/server/internal/artifacts"
	"github.com/m-sec-org/d-eyes/server/internal/behavior"
	"github.com/m-sec-org/d-eyes/server/internal/config"
	"github.com/m-sec-org/d-eyes/server/internal/metrics"
	"github.com/m-sec-org/d-eyes/server/internal/model"
	"github.com/m-sec-org/d-eyes/server/internal/scheduler"
	"github.com/m-sec-org/d-eyes/server/internal/store"
	"github.com/m-sec-org/d-eyes/server/internal/threatintel"
	sharedtelemetry "github.com/m-sec-org/d-eyes/server/pkg/telemetry"
)

// Service implements pb.AgentServiceServer.
type Service struct {
	pb.UnimplementedAgentServiceServer
	store       store.Store
	sched       *scheduler.Scheduler
	cfg         config.Config
	logger      *slog.Logger
	metrics     *metrics.Metrics
	artifactMgr *artifacts.Manager
	threatIntel *threatintel.Orchestrator
	behavior    *behavior.Recorder
	analyzer    *behavior.Analyzer
	graph       *behavior.GraphService
}

func NewService(cfg config.Config, st store.Store, sched *scheduler.Scheduler, logger *slog.Logger, m *metrics.Metrics, artifactMgr *artifacts.Manager, ti *threatintel.Orchestrator, recorder *behavior.Recorder, analyzer *behavior.Analyzer, graph *behavior.GraphService) *Service {
	return &Service{store: st, sched: sched, cfg: cfg, logger: logger, metrics: m, artifactMgr: artifactMgr, threatIntel: ti, behavior: recorder, analyzer: analyzer, graph: graph}
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
		telemetry := req.GetTelemetry()
		metric := behavior.HeartbeatMetric{
			AgentID:        agentID,
			Timestamp:      heartbeatTime,
			Load:           req.GetLoad(),
			RunningTasks:   append([]string(nil), req.GetRunningTasks()...),
			LatencyMs:      telemetry.GetLatencyMs(),
			CPUPercent:     telemetry.GetCpuPercent(),
			BlockedActions: append([]string(nil), telemetry.GetBlockedActions()...),
		}
		if s.behavior != nil {
			s.behavior.RecordHeartbeat(ctx, metric)
		}
		if s.analyzer != nil {
			s.analyzer.ProcessHeartbeat(ctx, metric)
		}
		if s.graph != nil {
			s.graph.HandleHeartbeat(ctx, metric)
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
		if errors.Is(err, scheduler.ErrNoTaskAvailable) || errors.Is(err, scheduler.ErrAgentAtCapacity) {
			break
		}
		if err != nil {
			return nil, err
		}
		if err := s.sched.MarkRunStarted(ctx, run.LeaseID); err != nil {
			return nil, err
		}
		md := make(map[string]string, len(task.Metadata))
		for k, v := range task.Metadata {
			md[k] = v
		}
		leases = append(leases, &pb.TaskLease{
			TaskId:              task.ID.String(),
			LeaseId:             run.LeaseID.String(),
			TaskType:            string(task.Type),
			Payload:             append([]byte(nil), task.Payload...),
			LeaseTimeoutSeconds: int64(s.cfg.Scheduler.LeaseTTL / time.Second),
			Profile:             task.Profile,
			Metadata:            md,
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
	tiSubmissions := make([]threatintel.SampleSubmission, 0)
	for _, art := range req.GetArtifacts() {
		artifacts = append(artifacts, model.Artifact{
			ID:        uuid.New(),
			TaskRunID: run.ID,
			Name:      art.GetName(),
			MIMEType:  art.GetContentType(),
			Blob:      append([]byte(nil), art.GetData()...),
		})
	}
	if s.artifactMgr != nil {
		tokenIDs := parseArtifactTokenMetadata(req.GetMetadata(), s.logger)
		for _, token := range tokenIDs {
			handle, err := s.artifactMgr.Consume(token)
			if err != nil {
				if s.logger != nil {
					s.logger.Warn("failed to consume artifact upload", "token", token.String(), "error", err)
				}
				continue
			}
			artifactID := uuid.New()
			artifacts = append(artifacts, model.Artifact{
				ID:        artifactID,
				TaskRunID: run.ID,
				Name:      handle.Filename,
				MIMEType:  handle.ContentType,
				Blob:      append([]byte(nil), handle.Data...),
			})
			meta := map[string]string{}
			if handle.ContentType != "" {
				meta["content_type"] = handle.ContentType
			}
			if handle.Encryption != "" {
				meta["encryption"] = handle.Encryption
			}
			hash := strings.ToLower(strings.TrimSpace(handle.Hash))
			if hash == "" && len(handle.Data) > 0 {
				sum := sha256.Sum256(handle.Data)
				hash = hex.EncodeToString(sum[:])
			}
			tiSubmissions = append(tiSubmissions, threatintel.SampleSubmission{
				ArtifactIDs: []uuid.UUID{artifactID},
				Hash:        hash,
				Filename:    handle.Filename,
				Size:        int64(len(handle.Data)),
				TaskRunID:   run.ID,
				AgentID:     run.AgentID,
				Metadata:    meta,
			})
		}
		if len(tokenIDs) > 0 {
			delete(req.Metadata, artifactTokensMetadataKey)
		}
	}
	if err := s.sched.CompleteTask(ctx, run, status, req.GetSummaryJson(), req.GetErrorMessage(), req.GetMetadata(), req.GetExitCode(), req.GetErrorCode(), artifacts); err != nil {
		return nil, err
	}
	if telemetryMeta := extractTelemetryMetadata(req.GetMetadata()); len(telemetryMeta) > 0 {
		payload := behavior.TaskTelemetry{
			AgentID:    run.AgentID,
			TaskID:     run.TaskID,
			Metadata:   telemetryMeta,
			ReceivedAt: time.Now().UTC(),
		}
		if s.behavior != nil {
			recPayload := payload
			recPayload.Metadata = copyStringMap(payload.Metadata)
			s.behavior.RecordTaskTelemetry(ctx, recPayload)
		}
		if s.analyzer != nil {
			anPayload := payload
			anPayload.Metadata = copyStringMap(payload.Metadata)
			s.analyzer.ProcessTaskTelemetry(ctx, anPayload)
		}
		if s.graph != nil {
			graphPayload := payload
			graphPayload.Metadata = copyStringMap(payload.Metadata)
			s.graph.HandleTaskTelemetry(ctx, graphPayload)
		}
	}
	if len(tiSubmissions) > 0 && s.threatIntel != nil && s.threatIntel.Enabled() {
		for _, submission := range tiSubmissions {
			submission.Metadata = mergeMetadataSubmission(submission.Metadata, req.GetMetadata())
			if _, err := s.threatIntel.SubmitSample(ctx, submission); err != nil && s.logger != nil {
				s.logger.Warn("failed to submit threat intel sample", "error", err)
			}
		}
	}
	return &pb.ReportResultResponse{Accepted: true}, nil
}

func mergeMetadataSubmission(base map[string]string, from map[string]string) map[string]string {
	if len(from) == 0 {
		return base
	}
	if base == nil {
		base = make(map[string]string, len(from))
	}
	for k, v := range from {
		if strings.HasPrefix(k, "threatintel.") {
			base[k] = v
		}
	}
	return base
}

const artifactTokensMetadataKey = "threatintel.artifact_tokens"

func parseArtifactTokenMetadata(md map[string]string, logger *slog.Logger) []uuid.UUID {
	raw := strings.TrimSpace(md[artifactTokensMetadataKey])
	if raw == "" {
		return nil
	}
	var tokens []string
	if err := json.Unmarshal([]byte(raw), &tokens); err != nil {
		if logger != nil {
			logger.Warn("invalid artifact token metadata", "error", err)
		}
		return nil
	}
	result := make([]uuid.UUID, 0, len(tokens))
	for _, token := range tokens {
		id, err := uuid.Parse(strings.TrimSpace(token))
		if err != nil {
			if logger != nil {
				logger.Warn("invalid artifact token uuid", "token", token, "error", err)
			}
			continue
		}
		result = append(result, id)
	}
	return result
}

func extractTelemetryMetadata(md map[string]string) map[string]string {
	if len(md) == 0 {
		return nil
	}
	keys := []string{
		sharedtelemetry.MetadataProcessTree,
		sharedtelemetry.MetadataNetConnections,
		sharedtelemetry.MetadataResourceUsage,
		sharedtelemetry.MetadataUserSessions,
		sharedtelemetry.MetadataBASteps,
		sharedtelemetry.MetadataSandboxStats,
	}
	result := make(map[string]string)
	for _, key := range keys {
		if val, ok := md[key]; ok && val != "" {
			result[key] = val
		}
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

func copyStringMap(src map[string]string) map[string]string {
	if len(src) == 0 {
		return nil
	}
	dst := make(map[string]string, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}
