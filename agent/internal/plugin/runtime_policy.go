package plugin

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"time"

	pluginmanifest "github.com/m-sec-org/d-eyes/server/pkg/pluginmanifest"
)

// Limits defines the maximum resources a plugin may request.
type Limits struct {
	MaxMilliCPU int           // e.g. 500 means 0.5 core. 0 disables CPU enforcement.
	MaxMemoryMi int           // in MiB. 0 disables memory enforcement.
	MaxTimeout  time.Duration // 0 disables timeout enforcement.
}

// Policy communicates how a plugin should be executed.
type Policy struct {
	SandboxRequired bool
	ResourceLimits  ResourceBudget
	Manifest        pluginmanifest.Manifest
}

// ResourceBudget is the parsed budget from manifest.Resources.
type ResourceBudget struct {
	MilliCPU int
	MemoryMi int
	Timeout  time.Duration
}

// Event represents lifecycle + observability hooks for plugins.
type Event struct {
	Type    string // installed | rollback | rejected
	Name    string
	Version string
	Reason  string
}

// Hook allows consumers to observe plugin lifecycle events.
type Hook interface {
	OnEvent(ctx context.Context, evt Event)
}

type Manager struct {
	mu         sync.Mutex
	installed  map[string]pluginmanifest.Manifest
	hooks      []Hook
	limits     Limits
	sandboxAll bool
}

// NewManager constructs a Manager with optional hooks and global limits.
func NewManager(limits Limits, sandboxRequired bool, hooks ...Hook) *Manager {
	return &Manager{
		installed:  make(map[string]pluginmanifest.Manifest),
		limits:     limits,
		hooks:      hooks,
		sandboxAll: sandboxRequired,
	}
}

// Apply verifies the manifest, enforces resource/target constraints, records install state,
// and returns the calculated Policy. If validation fails it emits a rejected event.
func (m *Manager) Apply(ctx context.Context, manifest pluginmanifest.Manifest) (Policy, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if err := m.validateTargets(manifest.Targets); err != nil {
		m.emit(ctx, Event{Type: "rejected", Name: manifest.Name, Version: manifest.Version, Reason: err.Error()})
		return Policy{}, err
	}
	budget, err := parseResourceBudget(manifest.Resources)
	if err != nil {
		m.emit(ctx, Event{Type: "rejected", Name: manifest.Name, Version: manifest.Version, Reason: err.Error()})
		return Policy{}, err
	}
	if err := enforceLimits(budget, m.limits); err != nil {
		m.emit(ctx, Event{Type: "rejected", Name: manifest.Name, Version: manifest.Version, Reason: err.Error()})
		return Policy{}, err
	}

	m.installed[manifest.Name] = manifest
	m.emit(ctx, Event{Type: "installed", Name: manifest.Name, Version: manifest.Version})

	return Policy{
		SandboxRequired: m.sandboxAll || sandboxFlag(manifest.Metadata),
		ResourceLimits:  budget,
		Manifest:        manifest,
	}, nil
}

// ApplyWithRollback returns policy plus a rollback func so callers can revert upon activation failure.
func (m *Manager) ApplyWithRollback(ctx context.Context, manifest pluginmanifest.Manifest) (Policy, func(), error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if err := m.validateTargets(manifest.Targets); err != nil {
		m.emit(ctx, Event{Type: "rejected", Name: manifest.Name, Version: manifest.Version, Reason: err.Error()})
		return Policy{}, nil, err
	}
	budget, err := parseResourceBudget(manifest.Resources)
	if err != nil {
		m.emit(ctx, Event{Type: "rejected", Name: manifest.Name, Version: manifest.Version, Reason: err.Error()})
		return Policy{}, nil, err
	}
	if err := enforceLimits(budget, m.limits); err != nil {
		m.emit(ctx, Event{Type: "rejected", Name: manifest.Name, Version: manifest.Version, Reason: err.Error()})
		return Policy{}, nil, err
	}

	prev, hadPrev := m.installed[manifest.Name]
	m.installed[manifest.Name] = manifest
	m.emit(ctx, Event{Type: "installed", Name: manifest.Name, Version: manifest.Version})

	rollback := func() {
		m.mu.Lock()
		defer m.mu.Unlock()
		if !hadPrev {
			delete(m.installed, manifest.Name)
			m.emit(context.Background(), Event{Type: "rollback", Name: manifest.Name, Version: manifest.Version, Reason: "removed"})
			return
		}
		m.installed[manifest.Name] = prev
		m.emit(context.Background(), Event{Type: "rollback", Name: manifest.Name, Version: manifest.Version, Reason: "restored previous version"})
	}

	return Policy{
		SandboxRequired: m.sandboxAll || sandboxFlag(manifest.Metadata),
		ResourceLimits:  budget,
		Manifest:        manifest,
	}, rollback, nil
}

func (m *Manager) validateTargets(targets []pluginmanifest.Target) error {
	if len(targets) == 0 {
		return nil
	}
	hostOS := runtime.GOOS
	hostArch := runtime.GOARCH
	for _, t := range targets {
		if !strings.EqualFold(t.OS, hostOS) {
			return fmt.Errorf("target os %s does not match host %s", t.OS, hostOS)
		}
		if !strings.EqualFold(t.Arch, hostArch) {
			return fmt.Errorf("target arch %s does not match host %s", t.Arch, hostArch)
		}
	}
	return nil
}

func parseResourceBudget(r pluginmanifest.ResourceLimits) (ResourceBudget, error) {
	b := ResourceBudget{}
	if r.CPU != "" {
		val, err := parseMilliCPU(r.CPU)
		if err != nil {
			return b, err
		}
		b.MilliCPU = val
	}
	if r.Memory != "" {
		val, err := parseMemoryMi(r.Memory)
		if err != nil {
			return b, err
		}
		b.MemoryMi = val
	}
	if r.Timeout != "" {
		dur, err := time.ParseDuration(r.Timeout)
		if err != nil {
			return b, fmt.Errorf("timeout must be duration: %w", err)
		}
		b.Timeout = dur
	}
	return b, nil
}

func enforceLimits(budget ResourceBudget, limits Limits) error {
	if limits.MaxMilliCPU > 0 && budget.MilliCPU > limits.MaxMilliCPU {
		return fmt.Errorf("requested cpu %dm exceeds max %dm", budget.MilliCPU, limits.MaxMilliCPU)
	}
	if limits.MaxMemoryMi > 0 && budget.MemoryMi > limits.MaxMemoryMi {
		return fmt.Errorf("requested memory %dMi exceeds max %dMi", budget.MemoryMi, limits.MaxMemoryMi)
	}
	if limits.MaxTimeout > 0 && budget.Timeout > limits.MaxTimeout {
		return fmt.Errorf("requested timeout %s exceeds max %s", budget.Timeout, limits.MaxTimeout)
	}
	return nil
}

func sandboxFlag(meta map[string]string) bool {
	if len(meta) == 0 {
		return false
	}
	if v, ok := meta["sandbox"]; ok && strings.EqualFold(v, "required") {
		return true
	}
	return false
}

func parseMilliCPU(val string) (int, error) {
	v := strings.TrimSpace(val)
	if v == "" {
		return 0, errors.New("cpu value is empty")
	}
	if strings.HasSuffix(v, "m") {
		num := strings.TrimSuffix(v, "m")
		out, err := atoi(num, "cpu")
		if err != nil {
			return 0, err
		}
		return out, nil
	}
	// whole cores
	cores, err := atoi(v, "cpu")
	if err != nil {
		return 0, err
	}
	return cores * 1000, nil
}

func parseMemoryMi(val string) (int, error) {
	v := strings.TrimSpace(val)
	if v == "" {
		return 0, errors.New("memory value is empty")
	}
	if strings.HasSuffix(strings.ToLower(v), "mi") {
		num := strings.TrimSuffix(strings.ToLower(v), "mi")
		out, err := atoi(num, "memory")
		if err != nil {
			return 0, err
		}
		return out, nil
	}
	return atoi(v, "memory")
}

func atoi(s string, field string) (int, error) {
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, fmt.Errorf("%s must be numeric", field)
		}
		n = n*10 + int(r-'0')
	}
	return n, nil
}

func (m *Manager) emit(ctx context.Context, evt Event) {
	for _, h := range m.hooks {
		h.OnEvent(ctx, evt)
	}
}
