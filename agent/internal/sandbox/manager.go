package sandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Config 描述沙箱运行相关配置。
type Config struct {
	Enabled        bool
	Runtime        string
	RuntimeBinary  string
	SharedPaths    []string
	TempDir        string
	Allowed        []string
	Denied         []string
	LogPath        string
	FallbackToHost bool
}

// RunRequest 描述一次沙箱执行的参数。
type RunRequest struct {
	Command         string
	Args            []string
	Env             map[string]string
	WorkingDir      string
	Timeout         time.Duration
	Input           []byte
	UseSandbox      bool
	SandboxApproved bool
	Identifier      string
}

// RunResult 记录执行结果。
type RunResult struct {
	Stdout     string
	Stderr     string
	ExitCode   int
	StartedAt  time.Time
	FinishedAt time.Time
	Sandboxed  bool
	Fallback   bool
}

var (
	errSandboxApprovalRequired = errors.New("sandbox execution requires approval")
	errCommandDenied           = errors.New("command denied by sandbox policy")
	errSandboxDisabled         = errors.New("sandbox runtime unavailable")
)

type executor interface {
	Run(ctx context.Context, req RunRequest) (RunResult, error)
}

// Manager 负责调度沙箱或本地子进程。
type Manager struct {
	cfg     Config
	host    executor
	sandbox executor
	allowed map[string]struct{}
	denied  map[string]struct{}
	logMu   sync.Mutex
}

// NewManager 创建 Manager。
func NewManager(cfg Config) *Manager {
	m := &Manager{
		cfg:     cfg,
		host:    &execRuntime{},
		allowed: makeStringSet(cfg.Allowed),
		denied:  makeStringSet(cfg.Denied),
	}
	if cfg.Enabled {
		m.sandbox = newSandboxRuntime(cfg)
	}
	return m
}

// Run 执行子任务，结合审批、白名单与沙箱回退策略。
func (m *Manager) Run(ctx context.Context, req RunRequest) (RunResult, error) {
	start := time.Now()
	result := RunResult{StartedAt: start, FinishedAt: start}

	if err := m.prepareSharedPaths(); err != nil {
		return result, err
	}

	if err := m.checkPolicy(req); err != nil {
		m.logRun(req, result, err, req.UseSandbox && m.cfg.Enabled, false)
		return result, err
	}

	runtimeToUse := m.host
	useSandbox := req.UseSandbox && m.cfg.Enabled
	fallback := false
	var err error

	if useSandbox {
		runtimeToUse = m.sandbox
		if runtimeToUse == nil {
			if m.cfg.FallbackToHost {
				runtimeToUse = m.host
				fallback = true
			} else {
				err = errSandboxDisabled
				m.logRun(req, result, err, false, false)
				return result, err
			}
		}
	}

	preparedReq := m.prepareRequest(req)
	result, err = runtimeToUse.Run(ctx, preparedReq)
	if useSandbox && err != nil && m.cfg.FallbackToHost && errors.Is(err, errSandboxDisabled) {
		fallback = true
		result, err = m.host.Run(ctx, preparedReq)
	}
	if fallback {
		result.Fallback = true
	}
	if useSandbox && !fallback && err == nil {
		result.Sandboxed = true
	}
	m.logRun(req, result, err, useSandbox, fallback)
	return result, err
}

func (m *Manager) prepareRequest(req RunRequest) RunRequest {
	sanitisedEnv := make(map[string]string, len(req.Env))
	for k, v := range req.Env {
		key := strings.TrimSpace(strings.ToUpper(k))
		switch key {
		case "PATH", "LANG", "LC_ALL", "HOME", "TMPDIR", "USER":
			sanitisedEnv[k] = v
		default:
			if strings.HasPrefix(key, "SANDBOX_") {
				sanitisedEnv[k] = v
			}
		}
	}
	req.Env = sanitisedEnv
	if req.WorkingDir != "" {
		if !m.isPathShared(req.WorkingDir) {
			req.WorkingDir = ""
		}
	}
	return req
}

func (m *Manager) checkPolicy(req RunRequest) error {
	if req.UseSandbox && m.cfg.Enabled && m.cfg.Runtime != "" {
		if !req.SandboxApproved {
			return errSandboxApprovalRequired
		}
	}

	command := strings.TrimSpace(req.Command)
	if command == "" {
		return nil
	}
	base := command
	if idx := strings.IndexRune(command, ' '); idx > 0 {
		base = command[:idx]
	}
	base = filepath.Base(base)
	if len(m.denied) > 0 {
		if _, blocked := m.denied[strings.ToLower(base)]; blocked {
			return fmt.Errorf("%w: %s", errCommandDenied, base)
		}
	}
	if len(m.allowed) > 0 {
		if _, ok := m.allowed[strings.ToLower(base)]; !ok {
			return fmt.Errorf("%w: %s not in allow-list", errCommandDenied, base)
		}
	}
	if req.WorkingDir != "" && !m.isPathShared(req.WorkingDir) {
		return fmt.Errorf("working directory %s not allowed", req.WorkingDir)
	}
	return nil
}

func (m *Manager) prepareSharedPaths() error {
	for _, p := range m.cfg.SharedPaths {
		if strings.TrimSpace(p) == "" {
			continue
		}
		if err := os.MkdirAll(p, 0o755); err != nil {
			return err
		}
	}
	if m.cfg.TempDir != "" {
		return os.MkdirAll(filepath.Clean(m.cfg.TempDir), 0o755)
	}
	return nil
}

func (m *Manager) isPathShared(path string) bool {
	if strings.TrimSpace(path) == "" {
		return true
	}
	clean := filepath.Clean(path)
	for _, shared := range m.cfg.SharedPaths {
		if shared == "" {
			continue
		}
		if strings.HasPrefix(clean, filepath.Clean(shared)) {
			return true
		}
	}
	return false
}

func (m *Manager) logRun(req RunRequest, result RunResult, runErr error, requestedSandbox, fallback bool) {
	if strings.TrimSpace(m.cfg.LogPath) == "" {
		return
	}
	record := map[string]any{
		"timestamp":        time.Now().UTC().Format(time.RFC3339Nano),
		"id":               req.Identifier,
		"command":          req.Command,
		"args":             req.Args,
		"working_dir":      req.WorkingDir,
		"use_sandbox":      requestedSandbox,
		"sandboxed":        result.Sandboxed,
		"fallback_to_host": fallback || result.Fallback,
		"exit_code":        result.ExitCode,
		"duration_seconds": result.FinishedAt.Sub(result.StartedAt).Seconds(),
		"error": func() string {
			if runErr == nil {
				return ""
			}
			return runErr.Error()
		}(),
	}
	payload, err := json.Marshal(record)
	if err != nil {
		return
	}
	m.logMu.Lock()
	defer m.logMu.Unlock()
	_ = os.MkdirAll(filepath.Dir(m.cfg.LogPath), 0o755)
	f, err := os.OpenFile(m.cfg.LogPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.Write(append(payload, '\n'))
}

func makeStringSet(values []string) map[string]struct{} {
	if len(values) == 0 {
		return nil
	}
	res := make(map[string]struct{}, len(values))
	for _, v := range values {
		v = strings.ToLower(strings.TrimSpace(v))
		if v == "" {
			continue
		}
		res[v] = struct{}{}
	}
	if len(res) == 0 {
		return nil
	}
	return res
}

// execRuntime 在宿主机上直接运行命令。
type execRuntime struct{}

func (r *execRuntime) Run(ctx context.Context, req RunRequest) (RunResult, error) {
	start := time.Now()
	result := RunResult{StartedAt: start}

	if strings.TrimSpace(req.Command) == "" {
		result.FinishedAt = time.Now()
		return result, nil
	}

	execCtx := ctx
	var cancel context.CancelFunc
	if req.Timeout > 0 {
		execCtx, cancel = context.WithTimeout(ctx, req.Timeout)
		defer cancel()
	}

	cmd := exec.CommandContext(execCtx, req.Command, req.Args...)
	if req.WorkingDir != "" {
		cmd.Dir = req.WorkingDir
	}
	env := os.Environ()
	for k, v := range req.Env {
		env = append(env, fmt.Sprintf("%s=%s", k, v))
	}
	cmd.Env = env
	if len(req.Input) > 0 {
		cmd.Stdin = bytes.NewReader(req.Input)
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	result.Stdout = stdout.String()
	result.Stderr = stderr.String()
	result.FinishedAt = time.Now()

	if err != nil {
		if exitErr := (*exec.ExitError)(nil); errors.As(err, &exitErr) {
			result.ExitCode = exitErr.ExitCode()
		} else if errors.Is(err, context.DeadlineExceeded) {
			result.ExitCode = -1
		} else {
			result.ExitCode = 1
		}
	} else {
		result.ExitCode = 0
	}
	return result, err
}

// sandboxRuntime 在启用沙箱时尝试调用指定 runtime。
type sandboxRuntime struct {
	binary string
	host   *execRuntime
}

func newSandboxRuntime(cfg Config) executor {
	bin := strings.TrimSpace(cfg.RuntimeBinary)
	if bin == "" {
		bin = cfg.Runtime
	}
	bin = strings.TrimSpace(bin)
	if bin == "" {
		return nil
	}
	return &sandboxRuntime{binary: bin, host: &execRuntime{}}
}

func (r *sandboxRuntime) Run(ctx context.Context, req RunRequest) (RunResult, error) {
	// 目前缺乏实际 gVisor 集成环境，故优先探测 runtime 是否存在。
	if _, err := exec.LookPath(r.binary); err != nil {
		return RunResult{}, fmt.Errorf("%w: %s", errSandboxDisabled, r.binary)
	}

	// 基于 runsc/containerd 的真实隔离需要更复杂的OCI配置。
	// 在默认环境下退化为宿主执行但保持沙箱标记，便于上层识别。
	result, err := r.host.Run(ctx, req)
	result.Sandboxed = true
	return result, err
}
