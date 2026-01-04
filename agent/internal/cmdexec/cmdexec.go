package cmdexec

import (
	"context"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/m-sec-org/d-eyes/agent/internal/sandbox"
	"github.com/m-sec-org/d-eyes/agent/pkg/config"
)

type contextKey string

const (
	identifierContextKey contextKey = "cmdexec.identifier"
)

// WithIdentifier attaches an identifier used for audit logging.
func WithIdentifier(ctx context.Context, identifier string) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, identifierContextKey, strings.TrimSpace(identifier))
}

func identifierFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	val := ctx.Value(identifierContextKey)
	identifier, _ := val.(string)
	return strings.TrimSpace(identifier)
}

type Policy struct {
	Allowed []string
	Denied  []string
	LogPath string
}

type Request struct {
	Command    string
	Args       []string
	Env        map[string]string
	WorkingDir string
	Timeout    time.Duration
	Input      []byte
	Identifier string
}

type Result struct {
	Stdout     string
	Stderr     string
	ExitCode   int
	StartedAt  time.Time
	FinishedAt time.Time
}

var (
	mu      sync.RWMutex
	manager = sandbox.NewManager(sandbox.Config{})
	policy  = Policy{}
)

func Configure(cfg config.Config) {
	loggingDisabled := false
	p := Policy{
		Allowed: append([]string(nil), cfg.Sandbox.AllowedCommands...),
		Denied:  append([]string(nil), cfg.Sandbox.DeniedCommands...),
		LogPath: strings.TrimSpace(cfg.Sandbox.LogPath),
	}
	if disablesLogging(p.LogPath) {
		p.LogPath = ""
		loggingDisabled = true
	}
	if !loggingDisabled && strings.TrimSpace(p.LogPath) == "" {
		outputDir := strings.TrimSpace(cfg.Output.Dir)
		if outputDir == "" {
			outputDir = config.Default().Output.Dir
		}
		p.LogPath = filepath.Join(outputDir, "audit", "command-exec.jsonl")
	}
	if allowsAllCommands(p.Allowed) {
		p.Allowed = nil
	} else if len(p.Allowed) == 0 {
		p.Allowed = defaultAllowedCommands()
	}
	SetPolicy(p)
}

func SetPolicy(p Policy) {
	cfg := sandbox.Config{
		Enabled: false,
		Allowed: append([]string(nil), p.Allowed...),
		Denied:  append([]string(nil), p.Denied...),
		LogPath: strings.TrimSpace(p.LogPath),
	}

	mu.Lock()
	defer mu.Unlock()
	policy = p
	manager = sandbox.NewManager(cfg)
}

func GetPolicy() Policy {
	mu.RLock()
	defer mu.RUnlock()
	return Policy{
		Allowed: append([]string(nil), policy.Allowed...),
		Denied:  append([]string(nil), policy.Denied...),
		LogPath: policy.LogPath,
	}
}

func Run(ctx context.Context, req Request) (Result, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	req.Command = strings.TrimSpace(req.Command)
	identifier := strings.TrimSpace(req.Identifier)
	if identifier == "" {
		identifier = identifierFromContext(ctx)
	}

	runReq := sandbox.RunRequest{
		Command:    req.Command,
		Args:       append([]string(nil), req.Args...),
		Env:        req.Env,
		WorkingDir: strings.TrimSpace(req.WorkingDir),
		Timeout:    req.Timeout,
		Input:      req.Input,
		Identifier: identifier,
	}

	mu.RLock()
	localManager := manager
	mu.RUnlock()

	runRes, err := localManager.Run(ctx, runReq)
	return Result{
		Stdout:     runRes.Stdout,
		Stderr:     runRes.Stderr,
		ExitCode:   runRes.ExitCode,
		StartedAt:  runRes.StartedAt,
		FinishedAt: runRes.FinishedAt,
	}, err
}

func allowsAllCommands(values []string) bool {
	for _, v := range values {
		v = strings.TrimSpace(strings.ToLower(v))
		switch v {
		case "*", "any", "all":
			return true
		}
	}
	return false
}

func disablesLogging(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "-", "off", "none", "false", "0", "disable", "disabled":
		return true
	default:
		return false
	}
}

func defaultAllowedCommands() []string {
	return []string{
		"ping",
		"grep",
		"sshd",
		"systemctl",
		"powershell",
		"redis-cli",
		"mysql",
		"mongo",
		"psql",
		"jboss-cli.sh",
		"wlst.sh",
		"sh",
		"cmd",
	}
}
