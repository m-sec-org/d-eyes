package backend

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/m-sec-org/d-eyes/agent/internal/detect/engine"
	goengine "github.com/m-sec-org/d-eyes/agent/internal/detect/engine/goengine"
	"github.com/m-sec-org/d-eyes/agent/internal/detect/rules"
	"github.com/m-sec-org/d-eyes/agent/yaraRules"
)

// Mode 控制规则引擎类型。
type Mode string

const (
	ModeAuto     Mode = "auto"
	ModeNative   Mode = "native"
	ModePortable Mode = "portable"
)

// Options 定义加载行为。
type Options struct {
	RulePath    string
	Mode        Mode
	VersionHint string
}

// Result 返回加载完成后的上下文。
type Result struct {
	Backend        Mode
	Bundle         engine.RuleBundle
	Manager        *rules.Manager
	Stats          goengine.BuildStats
	Fallback       bool
	FallbackReason string
}

// Load 根据配置加载规则束，提供统一的 pure Go 入口。
func Load(opts Options) (*Result, error) {
	requestedMode := normalizeMode(opts.Mode)
	fallback := false
	fallbackReason := ""

	loadWithFactory := func(factory rules.RuleEngineFactory) (*rules.Manager, engine.RuleBundle, goengine.BuildStats, error) {
		manager := rules.NewManager(rules.Config{
			EmbeddedFS: yaraRules.RulesFS,
			CustomDir:  sanitizeRulePath(opts.RulePath),
			Version:    opts.VersionHint,
			Factory:    factory,
		})
		bundle, err := manager.EnsureLoaded()
		if err != nil {
			return nil, nil, goengine.BuildStats{}, err
		}
		snapshot := manager.Snapshot()
		return manager, bundle, snapshot.Stats.Clone(), nil
	}

	mode := requestedMode
	var factory rules.RuleEngineFactory
	switch requestedMode {
	case ModeNative:
		factory = nativeFactory()
		if factory == nil {
			fallback = true
			fallbackReason = "native backend unavailable (build without yara_native), falling back to portable engine"
			mode = ModePortable
		}
	case ModeAuto:
		// Prefer native when available; otherwise fall back to portable with an observable reason.
		if factory = nativeFactory(); factory != nil {
			manager, bundle, stats, err := loadWithFactory(factory)
			if err == nil {
				return &Result{
					Backend:  ModeNative,
					Bundle:   bundle,
					Manager:  manager,
					Stats:    stats,
					Fallback: false,
				}, nil
			}
			fallback = true
			fallbackReason = fmt.Sprintf("native backend failed to load (%v), falling back to portable engine", err)
			mode = ModePortable
			factory = nil
		} else {
			fallback = true
			fallbackReason = "native backend unavailable (build without yara_native), falling back to portable engine"
			mode = ModePortable
		}
	}

	manager, bundle, stats, err := loadWithFactory(factory)
	if err != nil {
		return nil, err
	}
	return &Result{
		Backend:        mode,
		Bundle:         bundle,
		Manager:        manager,
		Stats:          stats,
		Fallback:       fallback,
		FallbackReason: fallbackReason,
	}, nil
}

func normalizeMode(mode Mode) Mode {
	switch strings.ToLower(string(mode)) {
	case string(ModeNative):
		return ModeNative
	case string(ModePortable), "":
		return ModePortable
	case string(ModeAuto):
		return ModeAuto
	default:
		return ModePortable
	}
}

func sanitizeRulePath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	info, err := os.Stat(path)
	if err != nil {
		return ""
	}
	if info.IsDir() {
		return path
	}
	return filepath.Dir(path)
}
