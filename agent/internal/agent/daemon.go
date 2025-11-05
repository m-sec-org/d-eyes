package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"time"

	internal "github.com/m-sec-org/d-eyes/agent/internal"
	"github.com/m-sec-org/d-eyes/agent/internal/agent/remote"
	"github.com/m-sec-org/d-eyes/agent/internal/model"
	"github.com/m-sec-org/d-eyes/agent/internal/tasks"
	"github.com/m-sec-org/d-eyes/agent/pkg/config"
	serverpb "github.com/m-sec-org/d-eyes/server/proto/agentservicepb"
)

// RunRemote 启动与 Server 协作的远程 Agent 循环。
func RunRemote(ctx context.Context, cfg config.RemoteConfig) error {
	if !cfg.Enabled {
		return errors.New("remote mode disabled in config")
	}
	remoteCfg := remote.RemoteConfig{
		ServerGRPCAddr:    cfg.ServerGRPCAddr,
		AgentToken:        cfg.AgentToken,
		AgentName:         cfg.AgentName,
		HeartbeatInterval: cfg.HeartbeatInterval,
		TLS: remote.TLSConfig{
			Enabled:  cfg.TLS.Enabled,
			CertFile: cfg.TLS.CertFile,
			KeyFile:  cfg.TLS.KeyFile,
			CAFile:   cfg.TLS.CAFile,
		},
	}
	client := remote.NewClient(remoteCfg)
	cacheDir := cfg.CacheDir
	if cacheDir == "" {
		cacheDir = defaultCacheDir()
	}
	store, err := remote.NewFileStore(cacheDir)
	if err != nil {
		return err
	}

	runner := &remoteRunner{
		cfg:       cfg,
		remoteCfg: remoteCfg,
		client:    client,
		store:     store,
		pollInterval: func() time.Duration {
			if cfg.TaskPollInterval > 0 {
				return cfg.TaskPollInterval
			}
			return 2 * time.Second
		}(),
	}

	return runner.run(ctx)
}

func defaultCacheDir() string {
	base := filepath.Join(os.TempDir(), "d-eyes", "remote-cache")
	_ = os.MkdirAll(base, 0o755)
	return base
}

type remoteRunner struct {
	cfg          config.RemoteConfig
	remoteCfg    remote.RemoteConfig
	client       *remote.Client
	store        *remote.FileStore
	pollInterval time.Duration

	running int32
}

func (r *remoteRunner) run(ctx context.Context) error {
	backoff := time.Second
	for {
		if err := r.runOnce(ctx); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			log.Printf("[remote] connection loop error: %v", err)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(backoff):
			}
			if backoff < 30*time.Second {
				backoff *= 2
			}
			continue
		}
		return nil
	}
}

func (r *remoteRunner) runOnce(ctx context.Context) error {
	dialCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if err := r.client.Connect(dialCtx); err != nil {
		return err
	}
	defer r.client.Close()

	meta := remote.Metadata{
		Name:         r.remoteCfg.AgentName,
		Platform:     runtime.GOOS,
		Version:      runtime.Version(),
		Capabilities: internal.TaskNames(),
		Labels:       map[string]string{"mode": "remote"},
	}
	if meta.Name == "" {
		if host, err := os.Hostname(); err == nil {
			meta.Name = host
		} else {
			meta.Name = fmt.Sprintf("d-eyes-agent-%d", time.Now().Unix())
		}
	}

	if _, err := r.client.Register(ctx, meta); err != nil {
		return err
	}

	hbCh := make(chan remote.HeartbeatPayload, 1)
	hbErrCh, err := r.client.StartHeartbeat(ctx, hbCh)
	if err != nil {
		return err
	}

	if err := r.flushPending(ctx); err != nil {
		log.Printf("[remote] flush pending results error: %v", err)
	}

	ticker := time.NewTicker(r.pollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-hbErrCh:
			return err
		case <-ticker.C:
			if err := r.flushPending(ctx); err != nil {
				log.Printf("[remote] flush pending results error: %v", err)
			}
			if err := r.pollOnce(ctx, hbCh); err != nil {
				return err
			}
		}
	}
}

func (r *remoteRunner) pollOnce(ctx context.Context, hbCh chan<- remote.HeartbeatPayload) error {
	resp, err := r.client.PullTasks(ctx, 1)
	if err != nil {
		return err
	}
	if len(resp.GetLeases()) == 0 {
		return nil
	}
	for _, lease := range resp.GetLeases() {
		atomic.AddInt32(&r.running, 1)
		select {
		case hbCh <- remote.HeartbeatPayload{Load: float64(atomic.LoadInt32(&r.running))}:
		default:
		}
		if err := r.processLease(ctx, lease); err != nil {
			log.Printf("[remote] process task %s error: %v", lease.GetTaskId(), err)
		}
		atomic.AddInt32(&r.running, -1)
		select {
		case hbCh <- remote.HeartbeatPayload{Load: float64(atomic.LoadInt32(&r.running))}:
		default:
		}
	}
	return nil
}

func (r *remoteRunner) processLease(ctx context.Context, lease *serverpb.TaskLease) error {
	runner, ok := internal.TaskRunnerByName(lease.GetTaskType())
	if !ok {
		return r.reportFailure(ctx, lease, fmt.Sprintf("unsupported task type %q", lease.GetTaskType()))
	}

	cfg := internal.GetGlobalConfig()
	req := tasks.TaskRequest{
		Config:     cfg,
		Flags:      map[string]any{},
		Quiet:      true,
		JSONOutput: false,
	}
	if len(lease.GetPayload()) > 0 {
		var payload map[string]any
		if err := json.Unmarshal(lease.GetPayload(), &payload); err != nil {
			log.Printf("[remote] invalid payload for task %s: %v", lease.GetTaskId(), err)
		} else {
			req.Flags = payload
			if profile, ok := payload["profile"].(string); ok {
				req.Profile = profile
			}
			if name, ok := payload["name"].(string); ok {
				req.Name = name
			}
		}
	}
	if req.Name == "" {
		req.Name = lease.GetTaskId()
	}

	req.ApplyDefaults(lease.GetTaskType())
	timeout := req.Timeout
	if timeout <= 0 {
		timeout = cfg.Performance.Timeout
	}
	ctxTask := ctx
	var cancel context.CancelFunc
	if timeout > 0 {
		ctxTask, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	summary, result, execErr := tasks.ExecuteWithResult(ctxTask, lease.GetTaskType(), runner, req, internal.GetReportManager())
	execModel := tasks.ToExecutionResult(summary, result, execErr)
	payloadBytes, _ := json.Marshal(execModel)

	agentID := r.client.AgentID()
	reqProto := &serverpb.ReportResultRequest{
		AgentId:      agentID,
		TaskId:       lease.GetTaskId(),
		LeaseId:      lease.GetLeaseId(),
		Status:       execModel.Status,
		ErrorMessage: execModel.Error,
		SummaryJson:  payloadBytes,
	}

	if err := r.store.Save(reqProto); err != nil {
		log.Printf("[remote] save result cache failed: %v", err)
	}
	if _, err := r.client.ReportResult(ctx, reqProto); err != nil {
		return err
	}
	if err := r.store.Delete(lease.GetLeaseId()); err != nil {
		log.Printf("[remote] delete cache failed: %v", err)
	}
	return nil
}

func (r *remoteRunner) reportFailure(ctx context.Context, lease *serverpb.TaskLease, message string) error {
	summary := model.ExecutionResult{
		Status: "failed",
		Summary: model.ExecutionSummary{
			Command:         lease.GetTaskType(),
			Status:          "failed",
			DurationSeconds: 0,
			ErrorMessage:    message,
		},
		Error:      message,
		ReportedAt: time.Now().UTC(),
	}
	payload, _ := json.Marshal(summary)
	req := &serverpb.ReportResultRequest{
		AgentId:      r.client.AgentID(),
		TaskId:       lease.GetTaskId(),
		LeaseId:      lease.GetLeaseId(),
		Status:       "failed",
		ErrorMessage: message,
		SummaryJson:  payload,
	}
	if err := r.store.Save(req); err != nil {
		log.Printf("[remote] save failure cache error: %v", err)
	}
	if _, err := r.client.ReportResult(ctx, req); err != nil {
		return err
	}
	_ = r.store.Delete(lease.GetLeaseId())
	return nil
}

func (r *remoteRunner) flushPending(ctx context.Context) error {
	pending, err := r.store.Pending()
	if err != nil {
		return err
	}
	for _, req := range pending {
		if _, err := r.client.ReportResult(ctx, req); err != nil {
			return err
		}
		if err := r.store.Delete(req.GetLeaseId()); err != nil {
			return err
		}
	}
	return nil
}
