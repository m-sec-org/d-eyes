package reporttemplates

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
	"log/slog"
)

// Manager persists report templates for reuse.
type Manager struct {
	mu          sync.RWMutex
	templates   map[uuid.UUID]*Template
	persistPath string
	log         *slog.Logger
}

// Template describes a report template.
type Template struct {
	ID          uuid.UUID `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	Format      string    `json:"format"`
	Body        string    `json:"body"`
	Owner       string    `json:"owner,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

var (
	// ErrNotFound indicates template not present.
	ErrNotFound = errors.New("report template: not found")
)

type persistPayload struct {
	Templates []Template `json:"templates"`
}

// New creates a Manager with optional persistence.
func New(path string, log *slog.Logger) (*Manager, error) {
	if log == nil {
		log = slog.New(slog.NewTextHandler(os.Stdout, nil))
	}
	m := &Manager{
		templates:   make(map[uuid.UUID]*Template),
		persistPath: path,
		log:         log,
	}
	if path != "" {
		if err := m.load(); err != nil {
			return nil, err
		}
	}
	return m, nil
}

// List returns templates sorted by updated time.
func (m *Manager) List() []Template {
	m.mu.RLock()
	defer m.mu.RUnlock()
	items := make([]Template, 0, len(m.templates))
	for _, tmpl := range m.templates {
		items = append(items, *clone(tmpl))
	}
	sort.Slice(items, func(i, j int) bool {
		a := items[i]
		b := items[j]
		if a.UpdatedAt.Equal(b.UpdatedAt) {
			return strings.Compare(a.Name, b.Name) < 0
		}
		return a.UpdatedAt.After(b.UpdatedAt)
	})
	return items
}

// Get returns a template by ID.
func (m *Manager) Get(id uuid.UUID) (*Template, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	item, ok := m.templates[id]
	if !ok {
		return nil, ErrNotFound
	}
	return clone(item), nil
}

// Create inserts a new template.
func (m *Manager) Create(input Template) (*Template, error) {
	if err := validate(input); err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	input.ID = uuid.New()
	input.CreatedAt = now
	input.UpdatedAt = now
	m.mu.Lock()
	defer m.mu.Unlock()
	m.templates[input.ID] = clone(&input)
	if err := m.persistLocked(); err != nil {
		return nil, err
	}
	return clone(&input), nil
}

// Update replaces an existing template.
func (m *Manager) Update(id uuid.UUID, input Template) (*Template, error) {
	if err := validate(input); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	current, ok := m.templates[id]
	if !ok {
		return nil, ErrNotFound
	}
	input.ID = id
	input.CreatedAt = current.CreatedAt
	input.UpdatedAt = time.Now().UTC()
	m.templates[id] = clone(&input)
	if err := m.persistLocked(); err != nil {
		return nil, err
	}
	return clone(&input), nil
}

// Delete removes a template.
func (m *Manager) Delete(id uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.templates[id]; !ok {
		return ErrNotFound
	}
	delete(m.templates, id)
	return m.persistLocked()
}

func validate(t Template) error {
	if strings.TrimSpace(t.Name) == "" {
		return errors.New("report template: name required")
	}
	if strings.TrimSpace(t.Format) == "" {
		return errors.New("report template: format required")
	}
	if strings.TrimSpace(t.Body) == "" {
		return errors.New("report template: body required")
	}
	return nil
}

func clone(src *Template) *Template {
	if src == nil {
		return nil
	}
	cp := *src
	return &cp
}

func (m *Manager) persistLocked() error {
	if m.persistPath == "" {
		return nil
	}
	payload := persistPayload{Templates: make([]Template, 0, len(m.templates))}
	for _, tmpl := range m.templates {
		payload.Templates = append(payload.Templates, *tmpl)
	}
	data, err := json.MarshalIndent(payload, "", "  ")
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
	var payload persistPayload
	if err := json.Unmarshal(data, &payload); err != nil {
		return err
	}
	for i := range payload.Templates {
		tmpl := payload.Templates[i]
		if tmpl.ID == uuid.Nil {
			tmpl.ID = uuid.New()
		}
		if tmpl.CreatedAt.IsZero() {
			tmpl.CreatedAt = time.Now().UTC()
		}
		if tmpl.UpdatedAt.IsZero() {
			tmpl.UpdatedAt = tmpl.CreatedAt
		}
		m.templates[tmpl.ID] = clone(&tmpl)
	}
	return nil
}
