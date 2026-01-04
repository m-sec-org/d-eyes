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
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	internal "github.com/m-sec-org/d-eyes/agent/internal"
	"github.com/m-sec-org/d-eyes/agent/internal/agent/adaptive"
	"github.com/m-sec-org/d-eyes/agent/internal/agent/eventstream"
	"github.com/m-sec-org/d-eyes/agent/internal/agent/remote"
	"github.com/m-sec-org/d-eyes/agent/internal/collector"
	"github.com/m-sec-org/d-eyes/agent/internal/model"
	"github.com/m-sec-org/d-eyes/agent/internal/tasks"
	"github.com/m-sec-org/d-eyes/agent/internal/telemetry"
	"github.com/m-sec-org/d-eyes/agent/pkg/artifacts"
	"github.com/m-sec-org/d-eyes/agent/pkg/config"
	"github.com/m-sec-org/d-eyes/agent/pkg/threatintel"
	serverpb "github.com/m-sec-org/d-eyes/server/proto/agentservicepb"
)

type remoteClient interface {
	Connect(context.Context) error
	Close() error
	Register(context.Context, remote.Metadata) (*serverpb.RegisterResponse, error)
	StartHeartbeat(context.Context, <-chan remote.HeartbeatPayload) (<-chan error, error)
	PullTasks(context.Context, int32) (*serverpb.PullTaskResponse, error)
	ReportResult(context.Context, *serverpb.ReportResultRequest) (*serverpb.ReportResultResponse, error)
	AgentID() string
}

type resultStore interface {
	Save(*serverpb.ReportResultRequest) error
	Delete(string) error
	Pending() ([]*serverpb.ReportResultRequest, error)
}

type taskResolver func(string) (tasks.TaskRunner, bool)

type ticker interface {
	C() <-chan time.Time
	Stop()
}

type timeSource interface {
	Now() time.Time
	After(time.Duration) <-chan time.Time
	NewTicker(time.Duration) ticker
}

type realTicker struct {
	t *time.Ticker
}

func (t realTicker) C() <-chan time.Time {
	return t.t.C
}

func (t realTicker) Stop() {
	t.t.Stop()
}

type realTimeSource struct{}

func (realTimeSource) Now() time.Time {
	return time.Now()
}

func (realTimeSource) After(d time.Duration) <-chan time.Time {
	return time.After(d)
}

func (realTimeSource) NewTicker(d time.Duration) ticker {
	return realTicker{t: time.NewTicker(d)}
}

var (
	runRemoteFunc       = runRemoteInternal
	newRemoteRunnerFunc = newRemoteRunner
)

// RunRemote 启动与 Server 协作的远程 Agent 循环。
func RunRemote(ctx context.Context, cfg config.RemoteConfig) error {
	return runRemoteFunc(ctx, cfg)
}

func runRemoteInternal(ctx context.Context, cfg config.RemoteConfig) error {
	internal.EnsureDefaultTaskRunners(nil)
	if !cfg.Enabled {
		return errors.New("remote mode disabled in config")
	}
	runner, err := newRemoteRunnerFunc(cfg)
	if err != nil {
		return err
	}
	return runner.run(ctx)
}

type remoteRunnerOption func(*remoteRunner)

const defaultConfigWatchInterval = 5 * time.Second

func newRemoteRunner(cfg config.RemoteConfig, opts ...remoteRunnerOption) (*remoteRunner, error) {
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
	cacheDir := cfg.CacheDir
	if cacheDir == "" {
		cacheDir = defaultCacheDir()
	}
	store, err := remote.NewFileStore(cacheDir)
	if err != nil {
		return nil, err
	}
	pollInterval := cfg.TaskPollInterval
	if pollInterval <= 0 {
		pollInterval = 2 * time.Second
	}
	runner := &remoteRunner{
		cfg:          cfg,
		remoteCfg:    remoteCfg,
		client:       remote.NewClient(remoteCfg),
		store:        store,
		pollInterval: pollInterval,
		timeSource:   realTimeSource{},
		resolveTask:  internal.TaskRunnerByName,
		throttle:     adaptive.NewController(cfg.Adaptive),
		cacheStats:   make(map[string]string),
	}
	for _, opt := range opts {
		if opt != nil {
			opt(runner)
		}
	}
	if runner.collectorFactory == nil {
		runner.collectorFactory = runner.defaultCollectorFactory
	}
	artifactClient, err := newArtifactClient(cfg)
	if err != nil {
		return nil, err
	}
	runner.artifactClient = artifactClient
	if runner.eventPipeline == nil {
		pipeline, err := eventstream.NewPipeline(0, cacheDir)
		if err != nil {
			return nil, fmt.Errorf("init event pipeline: %w", err)
		}
		runner.eventPipeline = pipeline
		pipelineHandler := pipeline.Handler()
		if runner.collectorHandler == nil {
			runner.collectorHandler = pipelineHandler
		} else {
			prev := runner.collectorHandler
			runner.collectorHandler = collector.EventHandlerFunc(func(ctx context.Context, event *collector.SystemEvent) error {
				if err := prev.HandleEvent(ctx, event); err != nil {
					return err
				}
				return pipelineHandler.HandleEvent(ctx, event)
			})
		}
	}
	if runner.client == nil {
		return nil, errors.New("remote runner: client is nil")
	}
	if runner.store == nil {
		return nil, errors.New("remote runner: result store is nil")
	}
	if runner.timeSource == nil {
		runner.timeSource = realTimeSource{}
	}
	if runner.resolveTask == nil {
		runner.resolveTask = internal.TaskRunnerByName
	}
	if runner.pollInterval <= 0 {
		runner.pollInterval = 2 * time.Second
	}
	if !runner.disableCollectorWatchers {
		runner.initCollectors()
	}
	if path := internal.LoadedConfigPath(); strings.TrimSpace(path) != "" {
		runner.startConfigWatcher(path)
	}
	return runner, nil
}

func defaultCacheDir() string {
	base := filepath.Join(os.TempDir(), "d-eyes", "remote-cache")
	_ = os.MkdirAll(base, 0o755)
	return base
}

func newArtifactClient(cfg config.RemoteConfig) (tasks.ArtifactClient, error) {
	base := strings.TrimSpace(cfg.ServerAPIBase)
	if base == "" {
		return nil, nil
	}
	client, err := artifacts.NewClient(artifacts.Config{
		BaseURL:    base,
		APIKey:     cfg.AgentToken,
		Timeout:    30 * time.Second,
		RetryCount: 3,
		UserAgent:  "d-eyes-agent",
	})
	if err != nil {
		return nil, fmt.Errorf("artifacts client: %w", err)
	}
	return client, nil
}

type remoteRunner struct {
	cfg          config.RemoteConfig
	remoteCfg    remote.RemoteConfig
	client       remoteClient
	store        resultStore
	pollInterval time.Duration
	timeSource   timeSource
	resolveTask  taskResolver
	throttle     *adaptive.Controller

	running    int32
	cacheMu    sync.RWMutex
	cacheStats map[string]string

	artifactClient tasks.ArtifactClient

	collectorMu              sync.Mutex
	collectorConfigs         []collector.Config
	collectorSvc             collectorController
	collectorHandler         collector.EventHandler
	collectorBaseCtx         context.Context
	collectorCtx             context.Context
	collectorCancel          context.CancelFunc
	collectorErr             string
	collectorWatcherStop     func()
	collectorFactory         func([]collector.Config) collectorController
	detectionSink            collector.DetectionSink
	disableCollectorWatchers bool

	configWatcherStop   context.CancelFunc
	configWatchInterval time.Duration

	eventPipeline     *eventstream.Pipeline
	eventUploaderStop context.CancelFunc
}

type collectorController interface {
	Start(context.Context, collector.EventHandler) error
	Stop(context.Context) error
	Status() []collector.CollectorStatus
}

func (r *remoteRunner) taskRunnerByName(name string) (tasks.TaskRunner, bool) {
	if r == nil || r.resolveTask == nil {
		return internal.TaskRunnerByName(name)
	}
	return r.resolveTask(name)
}

func (r *remoteRunner) now() time.Time {
	if r == nil || r.timeSource == nil {
		return time.Now()
	}
	return r.timeSource.Now()
}

func (r *remoteRunner) after(d time.Duration) <-chan time.Time {
	if r == nil || r.timeSource == nil {
		return time.After(d)
	}
	return r.timeSource.After(d)
}

func (r *remoteRunner) newTicker(d time.Duration) ticker {
	if r == nil || r.timeSource == nil {
		return realTimeSource{}.NewTicker(d)
	}
	return r.timeSource.NewTicker(d)
}

func (r *remoteRunner) defaultCollectorFactory(configs []collector.Config) collectorController {
	if len(configs) == 0 {
		return nil
	}
	opts := make([]collector.ServiceOption, 0, 1)
	if sink := r.ensureDetectionSink(); sink != nil {
		opts = append(opts, collector.WithDetectionSink(sink))
	}
	return collector.NewService(configs, opts...)
}

func (r *remoteRunner) initCollectors() {
	configs := collector.FromAppConfig(internal.GetGlobalConfig())
	r.updateCollectorConfigs(configs)
	r.collectorWatcherStop = internal.RegisterConfigWatcher(func(newCfg config.Config) {
		r.updateCollectorConfigs(collector.FromAppConfig(newCfg))
	})
}

func (r *remoteRunner) startCollectors(ctx context.Context) error {
	r.collectorMu.Lock()
	defer r.collectorMu.Unlock()
	r.collectorBaseCtx = ctx
	if r.collectorFactory == nil || len(r.collectorConfigs) == 0 || r.collectorCancel != nil {
		return nil
	}
	svc := r.collectorFactory(r.collectorConfigs)
	if svc == nil {
		return nil
	}
	handler := r.collectorHandler
	if handler == nil {
		handler = collector.EventHandlerFunc(func(context.Context, *collector.SystemEvent) error { return nil })
	}
	r.collectorSvc = svc
	collectorCtx, cancel := context.WithCancel(ctx)
	if err := svc.Start(collectorCtx, handler); err != nil {
		r.collectorSvc = nil
		r.collectorErr = err.Error()
		cancel()
		return err
	}
	r.collectorCancel = cancel
	r.collectorErr = ""
	return nil
}

func (r *remoteRunner) restartCollectorsLocked() {
	if r.collectorFactory == nil || len(r.collectorConfigs) == 0 || r.collectorBaseCtx == nil {
		return
	}
	if r.collectorCancel != nil {
		r.collectorCancel()
		r.collectorCancel = nil
	}
	if r.collectorSvc != nil {
		_ = r.collectorSvc.Stop(context.Background())
		r.collectorSvc = nil
	}
	svc := r.collectorFactory(r.collectorConfigs)
	if svc == nil {
		return
	}
	handler := r.collectorHandler
	if handler == nil {
		handler = collector.EventHandlerFunc(func(context.Context, *collector.SystemEvent) error { return nil })
	}
	collectorCtx, cancel := context.WithCancel(r.collectorBaseCtx)
	if err := svc.Start(collectorCtx, handler); err != nil {
		r.collectorErr = err.Error()
		cancel()
		return
	}
	r.collectorSvc = svc
	r.collectorCancel = cancel
	r.collectorErr = ""
}

func (r *remoteRunner) updateCollectorConfigs(configs []collector.Config) {
	r.collectorMu.Lock()
	defer r.collectorMu.Unlock()
	r.collectorConfigs = configs
	if r.collectorCancel != nil {
		r.restartCollectorsLocked()
	}
}

func (r *remoteRunner) dispatchAutoRespond(ctx context.Context, event *collector.SystemEvent, result collector.DetectionResult) {
	if r == nil || result.Action != collector.DetectionActionRespond {
		return
	}
	go func(evt *collector.SystemEvent, detection collector.DetectionResult) {
		if err := r.runRespondAutomation(evt, detection); err != nil {
			log.Printf("[remote] auto respond failed: %v", err)
		}
	}(cloneCollectorEvent(event), result)
}

func (r *remoteRunner) runRespondAutomation(event *collector.SystemEvent, detection collector.DetectionResult) error {
	runner, ok := r.taskRunnerByName("respond")
	if !ok || runner == nil {
		return fmt.Errorf("respond runner unavailable")
	}
	cfg := internal.GetGlobalConfig()
	req := tasks.TaskRequest{
		Profile:        detection.RespondProfile,
		Name:           fmt.Sprintf("auto-respond-%s", detection.RuleID),
		Config:         cfg,
		Flags:          map[string]any{"detection_rule": detection.RuleID, "detection_name": detection.Name},
		Metadata:       map[string]string{"automation": "respond", "detection.rule": detection.RuleID, "detection.name": detection.Name},
		Quiet:          true,
		JSONOutput:     true,
		ArtifactClient: r.artifactClient,
	}
	if detection.Severity != "" {
		req.Metadata["detection.severity"] = detection.Severity
	}
	if detection.Category != "" {
		req.Metadata["detection.category"] = detection.Category
	}
	if event != nil {
		req.Flags["detection_event_type"] = event.EventType
		req.Metadata["detection.event_type"] = event.EventType
		req.Metadata["detection.source"] = event.Source
		if event.Metadata != nil {
			if kind := event.Metadata["collector_kind"]; kind != "" {
				req.Metadata["collector_kind"] = kind
			}
			if name := event.Metadata["collector"]; name != "" {
				req.Metadata["collector_name"] = name
			}
		}
	}
	if req.Profile == "" {
		req.Profile = cfg.Tasks.Respond.Profile
	}
	req.ApplyDefaults("respond")
	if err := tasks.ValidateRequest("respond", &req); err != nil {
		return err
	}
	timeout := req.Timeout
	if timeout <= 0 {
		timeout = cfg.Performance.Timeout
		if timeout <= 0 {
			timeout = 2 * time.Minute
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	summary, result, execErr := tasks.ExecuteWithResult(ctx, "respond", runner, req, internal.GetReportManager())
	execModel := tasks.ToExecutionResult(summary, result, execErr)
	if r.eventPipeline != nil {
		payload := map[string]any{
			"detection": map[string]any{
				"rule":     detection.RuleID,
				"name":     detection.Name,
				"severity": detection.Severity,
				"category": detection.Category,
				"metadata": detection.Metadata,
				"tags":     detection.Tags,
			},
			"respond": execModel,
		}
		meta := map[string]string{
			"automation": "respond",
		}
		if event != nil && event.Metadata != nil {
			for _, key := range []string{"collector", "collector_kind"} {
				if val := event.Metadata[key]; val != "" {
					meta[key] = val
				}
			}
		}
		respEvent := &collector.SystemEvent{
			Timestamp: time.Now(),
			EventType: "agent.respond.automation",
			Source:    "collector.auto_respond",
			Metadata:  meta,
			Payload:   payload,
			Tags: map[string]string{
				"automation": "respond",
			},
		}
		_ = r.eventPipeline.Handle(respEvent)
	}
	return execErr
}

func cloneCollectorEvent(event *collector.SystemEvent) *collector.SystemEvent {
	if event == nil {
		return nil
	}
	out := &collector.SystemEvent{
		Timestamp: event.Timestamp,
		EventType: event.EventType,
		Source:    event.Source,
		Sequence:  event.Sequence,
	}
	if len(event.Metadata) > 0 {
		out.Metadata = make(map[string]string, len(event.Metadata))
		for k, v := range event.Metadata {
			out.Metadata[k] = v
		}
	}
	if len(event.Tags) > 0 {
		out.Tags = make(map[string]string, len(event.Tags))
		for k, v := range event.Tags {
			out.Tags[k] = v
		}
	}
	if len(event.Payload) > 0 {
		out.Payload = make(map[string]any, len(event.Payload))
		for k, v := range event.Payload {
			out.Payload[k] = v
		}
	}
	if len(event.Raw) > 0 {
		out.Raw = make(map[string]interface{}, len(event.Raw))
		for k, v := range event.Raw {
			out.Raw[k] = v
		}
	}
	return out
}

func (r *remoteRunner) shutdownCollectors() {
	if r.eventUploaderStop != nil {
		r.eventUploaderStop()
		r.eventUploaderStop = nil
	}
	if r.configWatcherStop != nil {
		r.configWatcherStop()
		r.configWatcherStop = nil
	}
	r.collectorMu.Lock()
	watcher := r.collectorWatcherStop
	r.collectorWatcherStop = nil
	if r.collectorCancel != nil {
		r.collectorCancel()
		r.collectorCancel = nil
	}
	if r.collectorSvc != nil {
		_ = r.collectorSvc.Stop(context.Background())
		r.collectorSvc = nil
	}
	r.collectorBaseCtx = nil
	r.collectorConfigs = nil
	r.collectorErr = ""
	r.collectorMu.Unlock()
	if watcher != nil {
		watcher()
	}
}

func (r *remoteRunner) collectorStatusSnapshot() ([]collector.CollectorStatus, string) {
	r.collectorMu.Lock()
	defer r.collectorMu.Unlock()
	if r.collectorSvc == nil {
		return nil, r.collectorErr
	}
	return r.collectorSvc.Status(), r.collectorErr
}

func (r *remoteRunner) startConfigWatcher(path string) {
	if strings.TrimSpace(path) == "" {
		return
	}
	interval := r.configWatchInterval
	if interval <= 0 {
		interval = defaultConfigWatchInterval
	}
	ctx, cancel := context.WithCancel(context.Background())
	if r.configWatcherStop != nil {
		r.configWatcherStop()
	}
	r.configWatcherStop = cancel
	go r.watchConfigFile(ctx, path, interval)
}

func (r *remoteRunner) watchConfigFile(ctx context.Context, path string, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	var lastStatErr string
	var lastLoadErr string
	var lastSig fileSignature
	var lastSigValid bool
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sig, err := statConfigSignature(path)
			if err != nil {
				msg := err.Error()
				if msg != lastStatErr {
					log.Printf("[remote] config watcher stat error: %v", err)
					lastStatErr = msg
				}
				continue
			}
			lastStatErr = ""
			if lastSigValid && sig == lastSig {
				continue
			}
			cfg, err := config.Load(path)
			if err != nil {
				msg := err.Error()
				if msg != lastLoadErr {
					log.Printf("[remote] reload config failed: %v", err)
					lastLoadErr = msg
				}
				continue
			}
			lastLoadErr = ""
			internal.SetGlobalConfig(cfg)
			lastSig = sig
			lastSigValid = true
		}
	}
}

type fileSignature struct {
	size    int64
	modTime time.Time
}

func statConfigSignature(path string) (fileSignature, error) {
	info, err := os.Stat(path)
	if err != nil {
		return fileSignature{}, err
	}
	return fileSignature{
		size:    info.Size(),
		modTime: info.ModTime(),
	}, nil
}

func (r *remoteRunner) run(ctx context.Context) error {
	if err := r.startCollectors(ctx); err != nil {
		log.Printf("[remote] collector start failed: %v", err)
	}
	defer r.shutdownCollectors()
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
			case <-r.after(backoff):
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

	labels := map[string]string{"mode": "remote"}
	for k, v := range r.cfg.Labels {
		key := strings.TrimSpace(k)
		val := strings.TrimSpace(v)
		if key == "" || val == "" {
			continue
		}
		labels[key] = val
	}
	meta := remote.Metadata{
		Name:         r.remoteCfg.AgentName,
		Platform:     runtime.GOOS,
		Version:      runtime.Version(),
		Capabilities: internal.TaskNames(),
		Labels:       labels,
	}
	if meta.Name == "" {
		if host, err := os.Hostname(); err == nil {
			meta.Name = host
		} else {
			meta.Name = fmt.Sprintf("d-eyes-agent-%d", r.now().Unix())
		}
	}

	if _, err := r.client.Register(ctx, meta); err != nil {
		return err
	}
	if id := strings.TrimSpace(r.client.AgentID()); id != "" {
		_ = os.Setenv("D_EYES_AGENT_ID", id)
	}
	if name := strings.TrimSpace(meta.Name); name != "" {
		_ = os.Setenv("D_EYES_AGENT_NAME", name)
	}
	if cancel := r.startEventUploader(ctx, meta.Name); cancel != nil {
		defer cancel()
	}

	telemetry.StartSystemSampler(ctx, 5*time.Second)

	hbCh := make(chan remote.HeartbeatPayload, 1)
	hbErrCh, err := r.client.StartHeartbeat(ctx, hbCh)
	if err != nil {
		return err
	}

	if err := r.flushPending(ctx); err != nil {
		log.Printf("[remote] flush pending results error: %v", err)
	}

	ticker := r.newTicker(r.pollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-hbErrCh:
			return err
		case <-ticker.C():
			if err := r.flushPending(ctx); err != nil {
				log.Printf("[remote] flush pending results error: %v", err)
			}
			if err := r.pollOnce(ctx, hbCh); err != nil {
				return err
			}
			if r.throttle != nil {
				r.pollInterval = r.throttle.NextDelay()
				ticker.Stop()
				ticker = r.newTicker(r.pollInterval)
			}
		}
	}
}

func (r *remoteRunner) pollOnce(ctx context.Context, hbCh chan<- remote.HeartbeatPayload) error {
	requestCount := int32(1)
	if r.throttle != nil {
		requestCount = int32(r.throttle.BoostPriority(1, telemetry.LatestCPUPercent()))
		if requestCount <= 0 {
			requestCount = 1
		}
	}
	r.enqueueHeartbeatPayload(hbCh, float64(atomic.LoadInt32(&r.running)), nil)
	resp, err := r.client.PullTasks(ctx, requestCount)
	if err != nil {
		if r.throttle != nil {
			r.throttle.RecordResult(ctx, err, 0, 0)
		}
		return err
	}
	if len(resp.GetLeases()) == 0 {
		if r.throttle != nil {
			r.throttle.RecordResult(ctx, nil, 0, telemetry.LatestCPUPercent())
		}
		return nil
	}
	for _, lease := range resp.GetLeases() {
		atomic.AddInt32(&r.running, 1)
		r.enqueueHeartbeatPayload(hbCh, float64(atomic.LoadInt32(&r.running)), []string{lease.GetTaskId()})
		if err := r.processLease(ctx, lease); err != nil {
			log.Printf("[remote] process task %s error: %v", lease.GetTaskId(), err)
		}
		atomic.AddInt32(&r.running, -1)
		r.enqueueHeartbeatPayload(hbCh, float64(atomic.LoadInt32(&r.running)), nil)
	}
	return nil
}

func (r *remoteRunner) processLease(ctx context.Context, lease *serverpb.TaskLease) error {
	runner, ok := r.taskRunnerByName(lease.GetTaskType())
	if !ok {
		return r.reportFailure(ctx, lease, fmt.Errorf("unsupported task type %q", lease.GetTaskType()))
	}

	cfg := internal.GetGlobalConfig()
	req := tasks.TaskRequest{
		Config:         cfg,
		Flags:          make(map[string]any),
		Metadata:       cloneStringMap(lease.GetMetadata()),
		Quiet:          true,
		JSONOutput:     false,
		ArtifactClient: r.artifactClient,
	}
	if prof := strings.TrimSpace(lease.GetProfile()); prof != "" {
		req.Profile = prof
	}
	if len(lease.GetPayload()) > 0 {
		var payload map[string]any
		if err := json.Unmarshal(lease.GetPayload(), &payload); err != nil {
			log.Printf("[remote] invalid payload for task %s: %v", lease.GetTaskId(), err)
		} else {
			applyRemotePayload(&req, payload)
		}
	}
	if req.Name == "" {
		req.Name = lease.GetTaskId()
	}

	req.ApplyDefaults(lease.GetTaskType())
	req.Config.Sandbox = mergeSandboxConfig(req.Config.Sandbox, r.cfg.Sandbox)
	if r.cfg.Sandbox.Enabled {
		req.Config.Tasks.BAS.SandboxEnabled = true
	}
	if err := tasks.ValidateRequest(lease.GetTaskType(), &req); err != nil {
		return r.reportFailure(ctx, lease, err)
	}

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
	execModel.Metadata = mergeStringMaps(execModel.Metadata, req.Metadata)
	if telemetryData := telemetry.CollectExecutionMetadata(ctxTask); len(telemetryData) > 0 {
		execModel.Metadata = mergeStringMaps(execModel.Metadata, telemetryData)
	}
	payloadBytes, _ := json.Marshal(execModel)

	agentID := r.client.AgentID()
	reqProto := &serverpb.ReportResultRequest{
		AgentId:      agentID,
		TaskId:       lease.GetTaskId(),
		LeaseId:      lease.GetLeaseId(),
		Status:       execModel.Status,
		ErrorMessage: execModel.Error,
		SummaryJson:  payloadBytes,
		Metadata:     cloneStringMap(execModel.Metadata),
		ExitCode:     execModel.ExitCode,
		ErrorCode:    execModel.ErrorCode,
	}
	r.updateCacheStats(execModel.Metadata)

	if err := r.store.Save(reqProto); err != nil {
		log.Printf("[remote] save result cache failed: %v", err)
	}
	if _, err := r.client.ReportResult(ctx, reqProto); err != nil {
		return err
	}
	if err := r.store.Delete(lease.GetLeaseId()); err != nil {
		log.Printf("[remote] delete cache failed: %v", err)
	}
	if r.throttle != nil {
		cpu := telemetry.LatestCPUPercent()
		r.throttle.RecordResult(ctx, execErr, 1, cpu)
	}
	return nil
}

func (r *remoteRunner) startEventUploader(ctx context.Context, agentName string) context.CancelFunc {
	if r.eventPipeline == nil {
		return nil
	}
	uploader := newEventUploader(r.eventPipeline, r.cfg, r.client.AgentID(), agentName)
	if uploader == nil {
		return nil
	}
	uploadCtx, cancel := context.WithCancel(ctx)
	go uploader.run(uploadCtx)
	r.eventUploaderStop = cancel
	return cancel
}

func (r *remoteRunner) enqueueHeartbeatPayload(hbCh chan<- remote.HeartbeatPayload, load float64, running []string) {
	if hbCh == nil {
		return
	}
	payload := remote.HeartbeatPayload{
		Load:     load,
		Metadata: r.collectHeartbeatMetadata(),
	}
	if len(running) > 0 {
		payload.RunningTasks = append([]string(nil), running...)
	}
	select {
	case hbCh <- payload:
	default:
	}
}

func (r *remoteRunner) reportFailure(ctx context.Context, lease *serverpb.TaskLease, execErr error) error {
	if execErr == nil {
		execErr = errors.New("unknown execution error")
	}
	message := execErr.Error()
	metadata := mergeStringMaps(nil, lease.GetMetadata())
	if telemetryData := telemetry.CollectExecutionMetadata(ctx); len(telemetryData) > 0 {
		metadata = mergeStringMaps(metadata, telemetryData)
	}
	summary := model.ExecutionResult{
		Status: "failed",
		Summary: model.ExecutionSummary{
			Command:         lease.GetTaskType(),
			Status:          "failed",
			DurationSeconds: 0,
			ErrorMessage:    message,
		},
		Error:      message,
		Metadata:   cloneStringMap(metadata),
		ExitCode:   1,
		ErrorCode:  "agent.remote_execution_failed",
		ReportedAt: r.now().UTC(),
	}
	payload, _ := json.Marshal(summary)
	req := &serverpb.ReportResultRequest{
		AgentId:      r.client.AgentID(),
		TaskId:       lease.GetTaskId(),
		LeaseId:      lease.GetLeaseId(),
		Status:       "failed",
		ErrorMessage: message,
		SummaryJson:  payload,
		Metadata:     cloneStringMap(metadata),
		ExitCode:     summary.ExitCode,
		ErrorCode:    summary.ErrorCode,
	}
	r.updateCacheStats(metadata)
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

func applyRemotePayload(req *tasks.TaskRequest, payload map[string]any) {
	if req == nil || payload == nil {
		return
	}
	flags := extractFlagMap(payload)
	if req.Flags == nil {
		req.Flags = make(map[string]any)
	}
	for k, v := range flags {
		req.Flags[k] = v
	}
	if v, ok := anyToString(payload["profile"]); ok && v != "" {
		req.Profile = v
	}
	if v, ok := anyToString(flags["profile"]); ok && v != "" {
		req.Profile = v
	}
	if v, ok := anyToString(payload["name"]); ok && v != "" {
		req.Name = v
	}
	if v, ok := anyToString(flags["name"]); ok && v != "" {
		req.Name = v
	}
	if v, ok := anyToString(flags["output-dir"]); ok && v != "" {
		req.OutputDir = v
	} else if v, ok := anyToString(payload["output-dir"]); ok && v != "" {
		req.OutputDir = v
	}
	if v, ok := anyToString(flags["format"]); ok && v != "" {
		req.Format = v
	} else if v, ok := anyToString(payload["format"]); ok && v != "" {
		req.Format = v
	}
	if v, ok := anyToBool(payload["quiet"]); ok {
		req.Quiet = v
	}
	if v, ok := anyToBool(flags["quiet"]); ok {
		req.Quiet = v
	}
	if v, ok := anyToBool(payload["json"]); ok {
		req.JSONOutput = v
	}
	if v, ok := anyToBool(flags["json"]); ok {
		req.JSONOutput = v
	}
	if v, ok := anyToBool(payload["debug"]); ok {
		req.Debug = v
	}
	if v, ok := anyToBool(flags["debug"]); ok {
		req.Debug = v
	}
	if d, ok := anyToDuration(payload["timeout"]); ok && d > 0 {
		req.Timeout = d
	}
	if d, ok := anyToDuration(flags["timeout"]); ok && d > 0 {
		req.Timeout = d
	}
	if v, ok := anyToString(payload["ti_mode"]); ok && v != "" {
		req.Config.ThreatIntel.Mode = threatintel.ParseMode(v)
	}
	if v, ok := anyToString(flags["ti-mode"]); ok && v != "" {
		req.Config.ThreatIntel.Mode = threatintel.ParseMode(v)
	}
}

func cloneStringMap(src map[string]string) map[string]string {
	if len(src) == 0 {
		return nil
	}
	dst := make(map[string]string, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

func mergeStringMaps(dst map[string]string, src map[string]string) map[string]string {
	if len(src) == 0 {
		return dst
	}
	if dst == nil {
		dst = make(map[string]string, len(src))
	}
	for k, v := range src {
		key := strings.TrimSpace(k)
		if key == "" {
			continue
		}
		dst[key] = v
	}
	return dst
}

func extractFlagMap(payload map[string]any) map[string]any {
	flags := make(map[string]any)
	if payload == nil {
		return flags
	}
	if nested, ok := payload["flags"]; ok {
		if m, ok := nested.(map[string]any); ok {
			for k, v := range m {
				flags[k] = v
			}
			return flags
		}
	}
	reserved := map[string]struct{}{
		"profile":    {},
		"name":       {},
		"timeout":    {},
		"quiet":      {},
		"json":       {},
		"output-dir": {},
		"format":     {},
		"flags":      {},
	}
	for k, v := range payload {
		if _, blocked := reserved[k]; blocked {
			continue
		}
		flags[k] = v
	}
	return flags
}

func anyToString(v any) (string, bool) {
	switch val := v.(type) {
	case string:
		return val, true
	case fmt.Stringer:
		return val.String(), true
	}
	return "", false
}

func anyToBool(v any) (bool, bool) {
	switch val := v.(type) {
	case bool:
		return val, true
	case string:
		s := strings.TrimSpace(strings.ToLower(val))
		switch s {
		case "true", "1", "yes", "y", "on":
			return true, true
		case "false", "0", "no", "n", "off":
			return false, true
		}
	case float64:
		return val != 0, true
	case int:
		return val != 0, true
	}
	return false, false
}

func anyToDuration(v any) (time.Duration, bool) {
	switch val := v.(type) {
	case string:
		d, err := time.ParseDuration(strings.TrimSpace(val))
		if err == nil {
			return d, true
		}
	case float64:
		return time.Duration(val * float64(time.Second)), true
	case int:
		return time.Duration(val) * time.Second, true
	}
	return 0, false
}

func mergeSandboxConfig(base config.SandboxConfig, override config.SandboxConfig) config.SandboxConfig {
	result := base
	if override.Enabled {
		result.Enabled = true
	}
	if override.Runtime != "" {
		result.Runtime = override.Runtime
	}
	if len(override.SharedPaths) > 0 {
		result.SharedPaths = append([]string(nil), override.SharedPaths...)
	}
	if override.TempDir != "" {
		result.TempDir = override.TempDir
	}
	if override.RuntimeBinary != "" {
		result.RuntimeBinary = override.RuntimeBinary
	}
	if len(override.AllowedCommands) > 0 {
		result.AllowedCommands = append([]string(nil), override.AllowedCommands...)
	}
	if len(override.DeniedCommands) > 0 {
		result.DeniedCommands = append([]string(nil), override.DeniedCommands...)
	}
	if override.RequireApproval {
		result.RequireApproval = true
	}
	if override.LogPath != "" {
		result.LogPath = override.LogPath
	}
	if !override.FallbackToHost {
		result.FallbackToHost = false
	}
	return result
}

func (r *remoteRunner) collectHeartbeatMetadata() map[string]string {
	stats := map[string]string{
		"telemetry.cpu_percent":     fmt.Sprintf("%.2f", telemetry.LatestCPUPercent()),
		"telemetry.memory_percent":  fmt.Sprintf("%.2f", telemetry.LatestMemoryPercent()),
		"telemetry.io_util_percent": fmt.Sprintf("%.2f", telemetry.LatestIOUtilization()),
	}
	if blocked := telemetry.CurrentBlockedActions(); len(blocked) > 0 {
		stats["telemetry.blocked_actions"] = strings.Join(blocked, ",")
	}
	r.cacheMu.RLock()
	for k, v := range r.cacheStats {
		stats[k] = v
	}
	r.cacheMu.RUnlock()
	statuses, collectorErr := r.collectorStatusSnapshot()
	if len(statuses) > 0 {
		stats["collectors.enabled"] = strconv.Itoa(len(statuses))
		for _, st := range statuses {
			prefix := fmt.Sprintf("collector.%s", st.Name)
			stats[prefix+".state"] = st.State
			if st.LastError != "" {
				stats[prefix+".error"] = st.LastError
			}
			for k, v := range st.Stats {
				stats[fmt.Sprintf("%s.%s", prefix, k)] = fmt.Sprint(v)
			}
			for k, v := range st.Metadata {
				stats[fmt.Sprintf("%s.meta.%s", prefix, sanitizeHeartbeatKey(k))] = v
			}
		}
	}
	if collectorErr != "" {
		stats["collector.error"] = collectorErr
	}
	if r.eventPipeline != nil {
		if chunk, count := r.eventPipeline.NextChunk(); chunk != "" {
			stats["collector.events.chunk"] = chunk
			stats["collector.events.chunk_count"] = strconv.Itoa(count)
		}
		pStats := r.eventPipeline.Stats()
		stats["collector.events.queue_depth"] = strconv.Itoa(pStats.QueueDepth)
		stats["collector.events.disk_backlog"] = strconv.FormatUint(pStats.DiskBacklog, 10)
		stats["collector.events.dropped"] = strconv.FormatUint(pStats.Dropped, 10)
	}
	return stats
}

func (r *remoteRunner) updateCacheStats(meta map[string]string) {
	if len(meta) == 0 {
		return
	}
	r.cacheMu.Lock()
	defer r.cacheMu.Unlock()
	if r.cacheStats == nil {
		r.cacheStats = make(map[string]string)
	}
	for k, v := range meta {
		if strings.HasPrefix(k, "cache.") {
			r.cacheStats[k] = v
		}
	}
}

func sanitizeHeartbeatKey(key string) string {
	if key == "" {
		return ""
	}
	key = strings.ReplaceAll(key, " ", "_")
	key = strings.ReplaceAll(key, "/", "_")
	key = strings.ReplaceAll(key, ":", "_")
	return key
}

func withRemoteClient(client remoteClient) remoteRunnerOption {
	return func(r *remoteRunner) {
		r.client = client
	}
}

func withResultStore(store resultStore) remoteRunnerOption {
	return func(r *remoteRunner) {
		r.store = store
	}
}

func withTimeSource(ts timeSource) remoteRunnerOption {
	return func(r *remoteRunner) {
		r.timeSource = ts
	}
}

func withTaskResolver(resolver taskResolver) remoteRunnerOption {
	return func(r *remoteRunner) {
		r.resolveTask = resolver
	}
}

func withPollInterval(d time.Duration) remoteRunnerOption {
	return func(r *remoteRunner) {
		r.pollInterval = d
	}
}

func withCollectorFactory(factory func([]collector.Config) collectorController) remoteRunnerOption {
	return func(r *remoteRunner) {
		r.collectorFactory = factory
	}
}

func withCollectorHandler(handler collector.EventHandler) remoteRunnerOption {
	return func(r *remoteRunner) {
		r.collectorHandler = handler
	}
}

func withoutCollectorWatchers() remoteRunnerOption {
	return func(r *remoteRunner) {
		r.disableCollectorWatchers = true
	}
}

func withEventPipeline(p *eventstream.Pipeline) remoteRunnerOption {
	return func(r *remoteRunner) {
		r.eventPipeline = p
	}
}

type autoRespondSink struct {
	runner *remoteRunner
}

func (s *autoRespondSink) OnDetection(ctx context.Context, event *collector.SystemEvent, result collector.DetectionResult) {
	if s == nil || s.runner == nil || result.Action != collector.DetectionActionRespond {
		return
	}
	s.runner.dispatchAutoRespond(ctx, event, result)
}

func (r *remoteRunner) ensureDetectionSink() collector.DetectionSink {
	if r == nil {
		return nil
	}
	if r.detectionSink == nil {
		r.detectionSink = &autoRespondSink{runner: r}
	}
	return r.detectionSink
}
