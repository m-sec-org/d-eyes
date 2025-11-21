package plugins

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	pluginmanifest "github.com/m-sec-org/d-eyes/server/pkg/pluginmanifest"
)

// Status represents plugin lifecycle states.
type Status string

const (
	StatusInstalled Status = "installed"
	StatusRejected  Status = "rejected"
	StatusRollback  Status = "rollback"
)

// Record represents a plugin manifest plus state metadata.
type Record struct {
	Manifest    pluginmanifest.Manifest `json:"manifest"`
	Status      Status                  `json:"status"`
	Reason      string                  `json:"reason,omitempty"`
	InstalledAt time.Time               `json:"installed_at"`
}

// Event mirrors Record for SSE consumers.
type Event struct {
	Type        string                  `json:"type"` // installed | rejected | rollback
	Manifest    pluginmanifest.Manifest `json:"manifest"`
	Reason      string                  `json:"reason,omitempty"`
	InstalledAt time.Time               `json:"installed_at"`
}

// Manager keeps plugin records in memory and emits events to listeners.
type Manager struct {
	mu      sync.RWMutex
	records map[string]Record   // current version keyed by name
	history map[string][]Record // previous versions for rollback
	hooks   []func(Event)
}

func NewManager() *Manager {
	return &Manager{
		records: make(map[string]Record),
		history: make(map[string][]Record),
	}
}

// UseHook registers a callback invoked on state changes.
func (m *Manager) UseHook(fn func(Event)) {
	if fn == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.hooks = append(m.hooks, fn)
}

// Install parses and validates the manifest then marks it installed.
func (m *Manager) Install(ctx context.Context, data []byte) (Record, error) {
	select {
	case <-ctx.Done():
		return Record{}, ctx.Err()
	default:
	}
	manifest, err := pluginmanifest.ParseManifest(data)
	if err != nil {
		rec := Record{Status: StatusRejected, Reason: err.Error(), InstalledAt: time.Now().UTC()}
		m.emit(Event{Type: string(StatusRejected), Manifest: manifest, Reason: rec.Reason, InstalledAt: rec.InstalledAt})
		return rec, err
	}
	rec := Record{
		Manifest:    manifest,
		Status:      StatusInstalled,
		InstalledAt: time.Now().UTC(),
	}

	m.mu.Lock()
	if current, ok := m.records[manifest.Name]; ok {
		m.history[manifest.Name] = append(m.history[manifest.Name], current)
	}
	m.records[manifest.Name] = rec
	m.mu.Unlock()
	m.emit(Event{Type: string(StatusInstalled), Manifest: manifest, InstalledAt: rec.InstalledAt})
	return rec, nil
}

// List returns all current plugin records.
func (m *Manager) List() []Record {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]Record, 0, len(m.records))
	for _, rec := range m.records {
		out = append(out, rec)
	}
	return out
}

// Get returns a plugin by name.
func (m *Manager) Get(name string) (Record, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	rec, ok := m.records[name]
	return rec, ok
}

// Rollback restores the prior version if available.
func (m *Manager) Rollback(ctx context.Context, name string) (Record, error) {
	select {
	case <-ctx.Done():
		return Record{}, ctx.Err()
	default:
	}
	m.mu.Lock()
	stack := m.history[name]
	if len(stack) == 0 {
		m.mu.Unlock()
		return Record{}, errors.New("no previous version to rollback")
	}
	prev := stack[len(stack)-1]
	m.history[name] = stack[:len(stack)-1]
	prev.Status = StatusRollback
	prev.InstalledAt = time.Now().UTC()
	m.records[name] = prev
	m.mu.Unlock()
	m.emit(Event{Type: string(StatusRollback), Manifest: prev.Manifest, Reason: "restored previous version", InstalledAt: prev.InstalledAt})
	return prev, nil
}

func (m *Manager) emit(evt Event) {
	for _, fn := range m.hooks {
		fn(evt)
	}
}

// MustFind raises error if plugin not present.
func MustFind(m *Manager, name string) (Record, error) {
	if m == nil {
		return Record{}, fmt.Errorf("plugin manager not initialized")
	}
	rec, ok := m.Get(name)
	if !ok {
		return Record{}, fmt.Errorf("plugin %s not found", name)
	}
	return rec, nil
}
