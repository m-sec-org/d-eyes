package rules

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"testing/fstest"
	"time"

	"github.com/m-sec-org/d-eyes/agent/internal/detect/engine"
	goengine "github.com/m-sec-org/d-eyes/agent/internal/detect/engine/goengine"
)

type stubBundle struct{}

func (stubBundle) Name() string    { return "stub" }
func (stubBundle) Version() string { return "v1" }
func (stubBundle) RuleCount() int  { return 1 }
func (stubBundle) Scan([]byte, engine.ScanOptions) ([]engine.Match, error) {
	return nil, nil
}

type fakeFactory struct {
	files   map[string][]byte
	version string
	err     error
}

func (f *fakeFactory) FromSources(files map[string][]byte, version string) (engine.RuleBundle, goengine.BuildStats, error) {
	f.files = files
	f.version = version
	stats := goengine.BuildStats{TotalRuleFiles: len(files), LoadedRuleFiles: len(files)}
	if f.err != nil {
		return nil, stats, f.err
	}
	return stubBundle{}, stats, nil
}

func withFactory(factory RuleEngineFactory, fn func()) {
	prev := getRuleEngineFactory()
	SetRuleEngineFactory(factory)
	defer SetRuleEngineFactory(prev)
	fn()
}

func TestEnsureLoadedUsesEmbeddedFS(t *testing.T) {
	embedded := fstest.MapFS{
		"rules/sample.yar": &fstest.MapFile{Data: []byte("rule sample { condition: true }")},
		"rules/ignore.txt": &fstest.MapFile{Data: []byte("noop")},
	}
	factory := &fakeFactory{}

	withFactory(factory, func() {
		mgr := NewManager(Config{EmbeddedFS: fs.FS(embedded), Version: "20250101"})
		bundle, err := mgr.EnsureLoaded()
		if err != nil {
			t.Fatalf("EnsureLoaded failed: %v", err)
		}
		if _, err := bundle.Scan(nil, engine.ScanOptions{}); err != nil {
			t.Fatalf("bundle scan should be safe: %v", err)
		}
		if len(factory.files) != 1 {
			t.Fatalf("expected 1 .yar file, got %d", len(factory.files))
		}
		if factory.version != "20250101" {
			t.Fatalf("version not propagated")
		}
		snap := mgr.Snapshot()
		if snap.Version != "20250101" || snap.Source != "embedded" {
			t.Fatalf("unexpected snapshot: %+v", snap)
		}
		if len(mgr.Sources()) != 1 {
			t.Fatalf("expected sources to be captured")
		}
	})
}

func TestEnsureLoadedPrefersCustomDirectory(t *testing.T) {
	dir := t.TempDir()
	custom := filepath.Join(dir, "custom.yar")
	if err := os.WriteFile(custom, []byte("rule custom { condition: true }"), 0o600); err != nil {
		t.Fatalf("write custom rule: %v", err)
	}
	factory := &fakeFactory{}

	withFactory(factory, func() {
		mgr := NewManager(Config{CustomDir: dir})
		if _, err := mgr.EnsureLoaded(); err != nil {
			t.Fatalf("EnsureLoaded custom failed: %v", err)
		}
		if len(factory.files) != 1 {
			t.Fatalf("expected custom file loaded")
		}
		if !factory.versionHasPrefix("custom-") {
			t.Fatalf("expected custom version prefix, got %s", factory.version)
		}
		if mgr.sourceLabel("hash") != "custom" {
			t.Fatalf("source label should be custom")
		}
	})
}

func (f *fakeFactory) versionHasPrefix(prefix string) bool {
	return len(f.version) >= len(prefix) && f.version[:len(prefix)] == prefix
}

func TestDigestDirectoryDeterministic(t *testing.T) {
	dir := t.TempDir()
	paths := []string{"a.yar", "b.yar"}
	for _, name := range paths {
		file := filepath.Join(dir, name)
		if err := os.WriteFile(file, []byte(name), 0o600); err != nil {
			t.Fatalf("write file: %v", err)
		}
		now := time.Unix(1700000000, 0)
		if err := os.Chtimes(file, now, now); err != nil {
			t.Fatalf("chtimes: %v", err)
		}
	}
	first, err := digestDirectory(dir)
	if err != nil {
		t.Fatalf("digestDirectory error: %v", err)
	}
	second, err := digestDirectory(dir)
	if err != nil {
		t.Fatalf("digestDirectory error: %v", err)
	}
	if first == "" || first != second {
		t.Fatalf("expected deterministic hash")
	}

	if _, err := digestDirectory(filepath.Join(dir, "missing")); err == nil {
		t.Fatalf("expected error for missing path")
	}
}
