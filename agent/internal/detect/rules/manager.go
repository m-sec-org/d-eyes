package rules

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/m-sec-org/d-eyes/agent/internal/detect/engine"
	"github.com/m-sec-org/d-eyes/agent/internal/detect/engine/goengine"
)

// Config configures rule manager behaviour.
type Config struct {
	EmbeddedFS fs.FS
	CustomDir  string
	Version    string
	Factory    RuleEngineFactory
}

// Manager orchestrates rule loading and hot updates.
type Manager struct {
	cfg         Config
	provider    *engine.ThreadSafeProvider
	factory     RuleEngineFactory
	mu          sync.Mutex
	lastHash    string
	lastLoad    time.Time
	snapshot    Snapshot
	lastSources map[string][]byte
}

// Snapshot captures the latest load stats.
type Snapshot struct {
	Stats      goengine.BuildStats
	Version    string
	Source     string
	CustomHash string
	LoadedAt   time.Time
}

// NewManager returns a ready to use rule manager.
func NewManager(cfg Config) *Manager {
	factory := cfg.Factory
	if factory == nil {
		factory = getRuleEngineFactory()
	}
	return &Manager{
		cfg:      cfg,
		provider: &engine.ThreadSafeProvider{},
		factory:  factory,
	}
}

// Provider exposes bundle provider for consumption.
func (m *Manager) Provider() engine.BundleProvider {
	return m.provider
}

// EnsureLoaded loads rules if not already initialised or if underlying files changed.
func (m *Manager) EnsureLoaded() (engine.RuleBundle, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	customHash := ""
	if m.cfg.CustomDir != "" {
		hash, err := digestDirectory(m.cfg.CustomDir)
		if err == nil {
			customHash = hash
		}
	}

	if m.provider.Version() != "" && customHash == m.lastHash {
		return m.provider.CurrentBundle()
	}

	files, version, err := m.collectSources(customHash)
	if err != nil {
		return nil, err
	}

	engineBundle, stats, err := m.factory.FromSources(files, version)
	if err != nil {
		return nil, err
	}

	m.provider.Update(engineBundle)
	m.lastHash = customHash
	m.lastLoad = time.Now()
	m.lastSources = cloneSources(files)
	m.snapshot = Snapshot{
		Stats:      stats.Clone(),
		Version:    version,
		Source:     m.sourceLabel(customHash),
		CustomHash: customHash,
		LoadedAt:   m.lastLoad,
	}
	log.Printf("yara: bundle loaded source=%s version=%s coverage=%.1f%% files=%d/%d loaded rules=%d skip=%v",
		m.snapshot.Source,
		version,
		stats.Coverage()*100,
		stats.LoadedRuleFiles,
		stats.TotalRuleFiles,
		stats.LoadedRules,
		stats.SkipReasons,
	)
	return engineBundle, nil
}

// Snapshot returns the latest load snapshot (best effort).
func (m *Manager) Snapshot() Snapshot {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.snapshot.clone()
}

// Sources returns a copy of the last loaded rule sources (path -> contents).
// Returns nil if no bundle has been loaded.
func (m *Manager) Sources() map[string][]byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.lastSources) == 0 {
		return nil
	}
	out := make(map[string][]byte, len(m.lastSources))
	for k, v := range m.lastSources {
		buf := make([]byte, len(v))
		copy(buf, v)
		out[k] = buf
	}
	return out
}

func (m *Manager) collectSources(customHash string) (map[string][]byte, string, error) {
	result := make(map[string][]byte)
	version := m.cfg.Version

	if customHash != "" && m.cfg.CustomDir != "" {
		err := filepath.WalkDir(m.cfg.CustomDir, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				return nil
			}
			if filepath.Ext(d.Name()) != ".yar" {
				return nil
			}
			data, readErr := os.ReadFile(path)
			if readErr != nil {
				return readErr
			}
			rel := filepath.Base(path)
			result[rel] = data
			return nil
		})
		if err == nil && len(result) > 0 {
			if version == "" {
				version = fmt.Sprintf("custom-%s", customHash[:8])
			}
			return result, version, nil
		}
	}

	if m.cfg.EmbeddedFS == nil {
		return nil, "", fmt.Errorf("no rule source available")
	}

	err := fs.WalkDir(m.cfg.EmbeddedFS, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if filepath.Ext(d.Name()) != ".yar" {
			return nil
		}
		data, readErr := fs.ReadFile(m.cfg.EmbeddedFS, path)
		if readErr != nil {
			return readErr
		}
		result[path] = data
		return nil
	})
	if err != nil {
		return nil, "", err
	}
	if version == "" {
		version = time.Now().UTC().Format("20060102T150405Z")
	}
	return result, version, nil
}

func (m *Manager) sourceLabel(customHash string) string {
	if customHash != "" && m.cfg.CustomDir != "" {
		return "custom"
	}
	return "embedded"
}

func (s Snapshot) clone() Snapshot {
	out := s
	out.Stats = s.Stats.Clone()
	return out
}

func cloneSources(src map[string][]byte) map[string][]byte {
	if len(src) == 0 {
		return nil
	}
	dst := make(map[string][]byte, len(src))
	for k, v := range src {
		buf := make([]byte, len(v))
		copy(buf, v)
		dst[k] = buf
	}
	return dst
}

// digestDirectory returns deterministic hash of file names/size/modtime.
func digestDirectory(dir string) (string, error) {
	stat, err := os.Stat(dir)
	if err != nil {
		return "", err
	}
	if !stat.IsDir() {
		return "", fmt.Errorf("%s is not a directory", dir)
	}
	hash := sha1.New()
	paths := make([]string, 0)
	err = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if filepath.Ext(d.Name()) != ".yar" {
			return nil
		}
		paths = append(paths, path)
		return nil
	})
	if err != nil {
		return "", err
	}
	sort.Strings(paths)
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			return "", err
		}
		io.WriteString(hash, path)
		io.WriteString(hash, info.ModTime().UTC().Format(time.RFC3339Nano))
		io.WriteString(hash, fmt.Sprintf("%d", info.Size()))
	}
	sum := hash.Sum(nil)
	return hex.EncodeToString(sum), nil
}

// RuleEngineFactory builds rule bundles from raw files.
type RuleEngineFactory interface {
	FromSources(files map[string][]byte, version string) (engine.RuleBundle, goengine.BuildStats, error)
}

var (
	ruleEngineFactory RuleEngineFactory = defaultRuleEngineFactory{}
	ruleFactoryMu     sync.RWMutex
)

// SetRuleEngineFactory overrides the global factory (nil restores default).
func SetRuleEngineFactory(factory RuleEngineFactory) {
	ruleFactoryMu.Lock()
	defer ruleFactoryMu.Unlock()
	if factory == nil {
		ruleEngineFactory = defaultRuleEngineFactory{}
		return
	}
	ruleEngineFactory = factory
}

func getRuleEngineFactory() RuleEngineFactory {
	ruleFactoryMu.RLock()
	defer ruleFactoryMu.RUnlock()
	return ruleEngineFactory
}

type defaultRuleEngineFactory struct{}

func (defaultRuleEngineFactory) FromSources(files map[string][]byte, version string) (engine.RuleBundle, goengine.BuildStats, error) {
	bundle, stats, err := goengine.FromDirectory(files, version)
	if err != nil {
		return nil, stats, err
	}
	return bundle, stats, nil
}
