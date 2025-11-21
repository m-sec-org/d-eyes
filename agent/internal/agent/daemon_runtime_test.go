package agent

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	internal "github.com/m-sec-org/d-eyes/agent/internal"
	"github.com/m-sec-org/d-eyes/agent/internal/agent/remote"
	"github.com/m-sec-org/d-eyes/agent/internal/tasks"
	"github.com/m-sec-org/d-eyes/agent/internal/telemetry"
	"github.com/m-sec-org/d-eyes/agent/pkg/config"
	serverpb "github.com/m-sec-org/d-eyes/server/proto/agentservicepb"
)

func TestRunRemoteDisabled(t *testing.T) {
	err := RunRemote(context.Background(), config.RemoteConfig{Enabled: false})
	require.Error(t, err)
	require.Contains(t, err.Error(), "disabled")
}

func TestRemoteProcessLeaseRespectsRunnerFactory(t *testing.T) {
	internal.SetGlobalConfig(config.Default())
	counter := &countingRunner{}
	restore := internal.OverrideRunnerFactoryForTesting(customRunnerFactory{
		base:    internal.DefaultRunnerFactory(),
		respond: counter,
	})
	defer restore()

	client := newFakeRemoteClient()
	runner := &remoteRunner{
		client: client,
		store:  newFakeResultStore(),
	}
	lease := &serverpb.TaskLease{
		TaskId:   "respond-job",
		LeaseId:  "lease-respond",
		TaskType: "respond",
	}
	payload := map[string]any{
		"flags": map[string]any{
			"targets": "127.0.0.1",
		},
	}
	rawPayload, err := json.Marshal(payload)
	require.NoError(t, err)
	lease.Payload = rawPayload
	responder, ok := internal.TaskRunnerByName("respond")
	require.True(t, ok)
	require.Equal(t, counter, responder)
	err = runner.processLease(context.Background(), lease)
	require.NoError(t, err)
	require.Equal(t, 1, counter.Calls())
}

func TestRemoteRunnerRunStopsOnContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	client := &fakeRemoteClient{connectErr: errors.New("dial failed")}
	store := newFakeResultStore()
	ts := newFakeTimeSource()
	runner := &remoteRunner{
		client:       client,
		store:        store,
		pollInterval: 5 * time.Millisecond,
		timeSource:   ts,
		resolveTask: func(string) (tasks.TaskRunner, bool) {
			return &fakeTaskRunner{}, true
		},
	}
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()
	orig := log.Writer()
	log.SetOutput(io.Discard)
	defer log.SetOutput(orig)
	err := runner.run(ctx)
	require.ErrorIs(t, err, context.Canceled)
}

func TestRemoteRunnerRunOnceProcessesLease(t *testing.T) {
	restoreSampler := telemetry.OverrideSystemSampler(func(context.Context, time.Duration) {})
	defer restoreSampler()
	restoreMetadata := telemetry.OverrideExecutionMetadataCollector(func(context.Context) map[string]string {
		return map[string]string{"exec_meta": "value"}
	})
	defer restoreMetadata()

	internal.SetGlobalConfig(config.Default())

	client := newFakeRemoteClient()
	payload := map[string]any{
		"profile": "remote-profile",
		"name":    "remote-task",
		"timeout": "2s",
		"flags": map[string]any{
			"custom": "value",
		},
		"json":  true,
		"quiet": true,
	}
	rawPayload, err := json.Marshal(payload)
	require.NoError(t, err)

	client.pullResponses = []*serverpb.PullTaskResponse{
		{
			Leases: []*serverpb.TaskLease{
				{
					TaskId:   "task-1",
					LeaseId:  "lease-1",
					TaskType: "test.command",
					Metadata: map[string]string{"from": "lease"},
					Payload:  rawPayload,
				},
			},
		},
	}
	store := newFakeResultStore()
	store.pendingQueue = []*serverpb.ReportResultRequest{
		{
			TaskId:  "stale-task",
			LeaseId: "stale-lease",
		},
	}
	ts := newFakeTimeSource()
	stubRunner := &fakeTaskRunner{
		result: tasks.TaskResult{
			Notes: []string{"runner note"},
			Metadata: map[string]string{
				"runner_meta": "true",
			},
		},
	}
	runner := &remoteRunner{
		cfg: config.RemoteConfig{
			Sandbox: config.SandboxConfig{
				Enabled:         true,
				Runtime:         "docker",
				RuntimeBinary:   "/usr/bin/docker",
				SharedPaths:     []string{"/tmp"},
				RequireApproval: true,
			},
		},
		client:       client,
		store:        store,
		pollInterval: 5 * time.Millisecond,
		timeSource:   ts,
		resolveTask: func(string) (tasks.TaskRunner, bool) {
			return stubRunner, true
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() {
		errCh <- runner.runOnce(ctx)
	}()

	select {
	case <-ts.tickerReady:
	case <-time.After(time.Second):
		t.Fatal("ticker not created")
	}
	ts.tick()
	client.triggerHeartbeatError(errors.New("hb gone"))

	err = <-errCh
	require.EqualError(t, err, "hb gone")

	require.Len(t, client.reportReqs, 2)
	require.Equal(t, "stale-task", client.reportReqs[0].GetTaskId())
	require.Equal(t, "task-1", client.reportReqs[1].GetTaskId())
	meta := client.reportReqs[1].GetMetadata()
	require.Equal(t, "true", meta["runner_meta"])
	require.Equal(t, "value", meta["exec_meta"])

	require.Contains(t, store.deleted, "stale-lease")
	require.Contains(t, store.deleted, "lease-1")
	require.Contains(t, store.saveCalls, "lease-1")
}

func TestReportFailureCachesResult(t *testing.T) {
	client := newFakeRemoteClient()
	store := newFakeResultStore()
	runner := &remoteRunner{
		client: client,
		store:  store,
	}
	lease := &serverpb.TaskLease{
		TaskId:  "task-fail",
		LeaseId: "lease-fail",
		Metadata: map[string]string{
			"source": "test",
		},
	}
	err := runner.reportFailure(context.Background(), lease, errors.New("boom"))
	require.NoError(t, err)
	require.Contains(t, store.deleted, "lease-fail")
	require.Len(t, client.reportReqs, 1)
	require.Equal(t, "agent.remote_execution_failed", client.reportReqs[0].GetErrorCode())
	require.Contains(t, client.reportReqs[0].GetMetadata(), "source")
}

func TestApplyRemotePayload(t *testing.T) {
	req := &tasks.TaskRequest{Flags: map[string]any{}, Config: config.Default()}
	payload := map[string]any{
		"profile": "remote",
		"name":    "job",
		"timeout": "3s",
		"json":    true,
		"quiet":   true,
		"flags": map[string]any{
			"custom": "abc",
		},
		"output-dir": "/tmp/out",
	}
	applyRemotePayload(req, payload)
	require.Equal(t, "remote", req.Profile)
	require.Equal(t, "job", req.Name)
	require.True(t, req.JSONOutput)
	require.True(t, req.Quiet)
	require.Equal(t, 3*time.Second, req.Timeout)
	require.Equal(t, "/tmp/out", req.OutputDir)
	require.Equal(t, "abc", req.Flags["custom"])
}

func TestExtractFlagMap(t *testing.T) {
	payload := map[string]any{
		"profile": "ignored",
		"flags": map[string]any{
			"name":   "should-pass",
			"custom": "ok",
		},
		"json":  true,
		"quiet": true,
	}
	flags := extractFlagMap(payload)
	require.Equal(t, "should-pass", flags["name"])
	require.Equal(t, "ok", flags["custom"])
	require.NotContains(t, flags, "profile")
	require.NotContains(t, flags, "json")
}

func TestAnyConversions(t *testing.T) {
	str, ok := anyToString(123)
	require.False(t, ok)
	str, ok = anyToString("value")
	require.True(t, ok)
	require.Equal(t, "value", str)

	b, ok := anyToBool("yes")
	require.True(t, ok)
	require.True(t, b)
	b, ok = anyToBool(0)
	require.True(t, ok)
	require.False(t, b)

	d, ok := anyToDuration("2s")
	require.True(t, ok)
	require.Equal(t, 2*time.Second, d)
	d, ok = anyToDuration(5)
	require.True(t, ok)
	require.Equal(t, 5*time.Second, d)
}

func TestMergeSandboxConfig(t *testing.T) {
	base := config.SandboxConfig{
		Enabled:     false,
		Runtime:     "runc",
		SharedPaths: []string{"/base"},
	}
	override := config.SandboxConfig{
		Enabled:         true,
		Runtime:         "docker",
		SharedPaths:     []string{"/override"},
		RequireApproval: true,
	}
	result := mergeSandboxConfig(base, override)
	require.True(t, result.Enabled)
	require.Equal(t, "docker", result.Runtime)
	require.Equal(t, []string{"/override"}, result.SharedPaths)
	require.True(t, result.RequireApproval)
}

// --- fakes ---

type fakeRemoteClient struct {
	connectErr        error
	registerErr       error
	startHeartbeatErr error
	pullErr           error
	reportErr         error
	pullResponses     []*serverpb.PullTaskResponse
	reportReqs        []*serverpb.ReportResultRequest
	hbErrCh           chan error
	agentID           string
}

func newFakeRemoteClient() *fakeRemoteClient {
	return &fakeRemoteClient{}
}

func (f *fakeRemoteClient) Connect(context.Context) error {
	return f.connectErr
}

func (f *fakeRemoteClient) Close() error { return nil }

func (f *fakeRemoteClient) Register(_ context.Context, meta remote.Metadata) (*serverpb.RegisterResponse, error) {
	if f.registerErr != nil {
		return nil, f.registerErr
	}
	if f.agentID == "" {
		if meta.Name != "" {
			f.agentID = "agent-" + meta.Name
		} else {
			f.agentID = "agent-test"
		}
	}
	return &serverpb.RegisterResponse{AgentId: f.agentID}, nil
}

func (f *fakeRemoteClient) StartHeartbeat(ctx context.Context, payloadCh <-chan remote.HeartbeatPayload) (<-chan error, error) {
	if f.startHeartbeatErr != nil {
		return nil, f.startHeartbeatErr
	}
	if f.hbErrCh == nil {
		f.hbErrCh = make(chan error, 1)
	}
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case _, ok := <-payloadCh:
				if !ok {
					return
				}
			}
		}
	}()
	return f.hbErrCh, nil
}

func (f *fakeRemoteClient) PullTasks(context.Context, int32) (*serverpb.PullTaskResponse, error) {
	if len(f.pullResponses) == 0 {
		return &serverpb.PullTaskResponse{}, f.pullErr
	}
	resp := f.pullResponses[0]
	f.pullResponses = f.pullResponses[1:]
	return resp, f.pullErr
}

func (f *fakeRemoteClient) ReportResult(_ context.Context, req *serverpb.ReportResultRequest) (*serverpb.ReportResultResponse, error) {
	cp := *req
	f.reportReqs = append(f.reportReqs, &cp)
	if f.reportErr != nil {
		return nil, f.reportErr
	}
	return &serverpb.ReportResultResponse{Accepted: true}, nil
}

func (f *fakeRemoteClient) AgentID() string {
	if f.agentID == "" {
		return "agent-default"
	}
	return f.agentID
}

func (f *fakeRemoteClient) triggerHeartbeatError(err error) {
	if f.hbErrCh != nil {
		f.hbErrCh <- err
	}
}

type fakeResultStore struct {
	mu           sync.Mutex
	saved        map[string]*serverpb.ReportResultRequest
	pendingQueue []*serverpb.ReportResultRequest
	deleted      []string
	saveCalls    []string
}

func newFakeResultStore() *fakeResultStore {
	return &fakeResultStore{
		saved: make(map[string]*serverpb.ReportResultRequest),
	}
}

func (s *fakeResultStore) Save(req *serverpb.ReportResultRequest) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *req
	s.saved[req.GetLeaseId()] = &cp
	s.saveCalls = append(s.saveCalls, req.GetLeaseId())
	return nil
}

func (s *fakeResultStore) Delete(leaseID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deleted = append(s.deleted, leaseID)
	delete(s.saved, leaseID)
	return nil
}

func (s *fakeResultStore) Pending() ([]*serverpb.ReportResultRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*serverpb.ReportResultRequest, len(s.pendingQueue))
	copy(out, s.pendingQueue)
	s.pendingQueue = nil
	return out, nil
}

type fakeTimeSource struct {
	now         time.Time
	ticker      *fakeTicker
	tickerReady chan struct{}
}

func newFakeTimeSource() *fakeTimeSource {
	return &fakeTimeSource{
		now:         time.Unix(0, 0),
		tickerReady: make(chan struct{}, 1),
	}
}

func (f *fakeTimeSource) Now() time.Time {
	return f.now
}

func (f *fakeTimeSource) After(time.Duration) <-chan time.Time {
	ch := make(chan time.Time, 1)
	ch <- f.now
	return ch
}

func (f *fakeTimeSource) NewTicker(time.Duration) ticker {
	ft := newFakeTicker()
	f.ticker = ft
	f.tickerReady <- struct{}{}
	return ft
}

func (f *fakeTimeSource) tick() {
	if f.ticker != nil {
		f.ticker.tick(f.now)
	}
}

type fakeTicker struct {
	ch       chan time.Time
	stopOnce sync.Once
}

func newFakeTicker() *fakeTicker {
	return &fakeTicker{ch: make(chan time.Time, 1)}
}

func (t *fakeTicker) C() <-chan time.Time { return t.ch }

func (t *fakeTicker) Stop() {
	t.stopOnce.Do(func() {
		close(t.ch)
	})
}

func (t *fakeTicker) tick(now time.Time) {
	select {
	case t.ch <- now:
	default:
	}
}

type fakeTaskRunner struct {
	mu     sync.Mutex
	called int
	result tasks.TaskResult
	err    error
}

func (f *fakeTaskRunner) Run(context.Context, tasks.TaskRequest) (tasks.TaskResult, error) {
	f.mu.Lock()
	f.called++
	f.mu.Unlock()
	if f.err != nil {
		return tasks.TaskResult{}, f.err
	}
	return f.result, nil
}
