package rules

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
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
}

// Manager orchestrates rule loading and hot updates.
type Manager struct {
	cfg      Config
	provider *engine.ThreadSafeProvider
	mu       sync.Mutex
	lastHash string
	lastLoad time.Time
}

// NewManager returns a ready to use rule manager.
func NewManager(cfg Config) *Manager {
	return &Manager{
		cfg:      cfg,
		provider: &engine.ThreadSafeProvider{},
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

	engineBundle, err := goengine.FromDirectory(files, version)
	if err != nil {
		return nil, err
	}

	m.provider.Update(engineBundle)
	m.lastHash = customHash
	m.lastLoad = time.Now()
	return engineBundle, nil
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
