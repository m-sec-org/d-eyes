package auditlog

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Event captures a single audit entry.
type Event struct {
	ID        uuid.UUID         `json:"id"`
	Timestamp time.Time         `json:"timestamp"`
	Actor     string            `json:"actor"`
	Role      string            `json:"role"`
	Action    string            `json:"action"`
	Resource  string            `json:"resource"`
	Result    string            `json:"result"`
	Metadata  map[string]string `json:"metadata,omitempty"`
}

// Filter allows querying by fields.
type Filter struct {
	Actor    string
	Resource string
	Action   string
	Limit    int
}

// Manager stores events in-memory with optional persistence.
type Manager struct {
	mu          sync.RWMutex
	events      []Event
	persistPath string
	capacity    int
}

// New creates a manager.
func New(path string, capacity int) (*Manager, error) {
	if capacity <= 0 {
		capacity = 2000
	}
	m := &Manager{persistPath: path, capacity: capacity}
	if path != "" {
		if err := m.load(); err != nil {
			return nil, err
		}
	}
	return m, nil
}

// Record appends an event.
func (m *Manager) Record(event Event) {
	if event.ID == uuid.Nil {
		event.ID = uuid.New()
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}
	event.Actor = strings.TrimSpace(event.Actor)
	event.Role = strings.TrimSpace(event.Role)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append([]Event{event}, m.events...)
	if len(m.events) > m.capacity {
		m.events = m.events[:m.capacity]
	}
	_ = m.persistLocked()
}

// List returns events matching the filter.
func (m *Manager) List(filter Filter) []Event {
	m.mu.RLock()
	defer m.mu.RUnlock()
	actor := strings.ToLower(strings.TrimSpace(filter.Actor))
	resource := strings.ToLower(strings.TrimSpace(filter.Resource))
	action := strings.ToLower(strings.TrimSpace(filter.Action))
	limit := filter.Limit
	if limit <= 0 || limit > m.capacity {
		limit = 200
	}
	result := make([]Event, 0, limit)
	for _, evt := range m.events {
		if actor != "" && !strings.Contains(strings.ToLower(evt.Actor), actor) {
			continue
		}
		if resource != "" && !strings.Contains(strings.ToLower(evt.Resource), resource) {
			continue
		}
		if action != "" && !strings.Contains(strings.ToLower(evt.Action), action) {
			continue
		}
		result = append(result, evt)
		if len(result) >= limit {
			break
		}
	}
	return result
}

func (m *Manager) persistLocked() error {
	if m.persistPath == "" {
		return nil
	}
	data, err := json.MarshalIndent(m.events, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(m.persistPath), 0o755); err != nil {
		return err
	}
	tmp := m.persistPath + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, m.persistPath)
}

func (m *Manager) load() error {
	data, err := os.ReadFile(m.persistPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	var events []Event
	if err := json.Unmarshal(data, &events); err != nil {
		return err
	}
	sort.Slice(events, func(i, j int) bool {
		return events[i].Timestamp.After(events[j].Timestamp)
	})
	if len(events) > m.capacity {
		events = events[:m.capacity]
	}
	m.events = events
	return nil
}
