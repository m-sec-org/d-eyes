//go:build linux

package collector

import (
	"bytes"
	"encoding/binary"
	"os"
	"strings"
	"testing"
	"time"
)

func TestConvertEBPFEvent(t *testing.T) {
	var raw syscallEvent
	raw.Timestamp = 123456789
	raw.PID = 42
	raw.TGID = 84
	raw.UID = 1000
	raw.GID = 2000
	raw.CgroupID = 777
	raw.EventType = ebpfEventTypeExec
	raw.Aux = 7
	copy(raw.Comm[:], []byte("bash\x00"))

	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.LittleEndian, raw); err != nil {
		t.Fatalf("binary.Write: %v", err)
	}
	event, ts, err := convertEBPFEvent(buf.Bytes(), "ebpf-test", "diag-ebpf")
	if err != nil {
		t.Fatalf("convertEBPFEvent error: %v", err)
	}
	if ts != raw.Timestamp {
		t.Fatalf("timestamp mismatch: got %d want %d", ts, raw.Timestamp)
	}
	if event.EventType != "process.exec" {
		t.Fatalf("unexpected event type: %s", event.EventType)
	}
	if event.Source != "ebpf-test" {
		t.Fatalf("unexpected source: %s", event.Source)
	}
	if pid, ok := event.Payload["pid"].(uint32); !ok || pid != raw.PID {
		t.Fatalf("unexpected pid payload: %+v", event.Payload["pid"])
	}
	if comm, ok := event.Payload["comm"].(string); !ok || comm != "bash" {
		t.Fatalf("unexpected comm payload: %+v", event.Payload["comm"])
	}
	if uid, ok := event.Payload["uid"].(uint32); !ok || uid != raw.UID {
		t.Fatalf("unexpected uid payload: %+v", event.Payload["uid"])
	}
	if gid, ok := event.Payload["gid"].(uint32); !ok || gid != raw.GID {
		t.Fatalf("unexpected gid payload: %+v", event.Payload["gid"])
	}
	if metaUID := event.Metadata["process.uid"]; metaUID != "1000" {
		t.Fatalf("expected process uid metadata, got %s", metaUID)
	}
	if metaGID := event.Metadata["process.gid"]; metaGID != "2000" {
		t.Fatalf("expected process gid metadata, got %s", metaGID)
	}
	if backend := event.Metadata["backend"]; backend != "ebpf" {
		t.Fatalf("unexpected backend metadata: %s", backend)
	}
	if collector := event.Metadata["collector"]; collector != "diag-ebpf" {
		t.Fatalf("unexpected collector metadata: %s", collector)
	}
}

func TestPerfBufferSizeSettings(t *testing.T) {
	size := perfBufferSize(map[string]any{"perf_buffer_size": 8192})
	if size != 8192 {
		t.Fatalf("expected explicit size, got %d", size)
	}
	pages := perfBufferSize(map[string]any{"perf_buffer_pages": 2})
	if pages != os.Getpagesize()*2 {
		t.Fatalf("expected 2 pages, got %d", pages)
	}
	defaultSize := perfBufferSize(nil)
	if defaultSize != os.Getpagesize()*8 {
		t.Fatalf("unexpected default size: %d", defaultSize)
	}
}

func TestConvertEBPFEventRejectsShortSample(t *testing.T) {
	if _, _, err := convertEBPFEvent([]byte{0x1, 0x2}, "src", "collector"); err == nil {
		t.Fatalf("expected error for undersized sample")
	}
}

func TestPerfBufferSizeFallbacks(t *testing.T) {
	pages := os.Getpagesize()
	size := perfBufferSize(map[string]any{
		"perf_buffer_size":  0,
		"perf_buffer_pages": "4",
	})
	if size != pages*4 {
		t.Fatalf("expected fallback to perf_buffer_pages, got %d", size)
	}
	defaulted := perfBufferSize(map[string]any{
		"perf_buffer_size":  -1,
		"perf_buffer_pages": 0,
	})
	if defaulted != pages*8 {
		t.Fatalf("expected default pages fallback, got %d", defaulted)
	}
}

func TestInspectEBPFEnvironmentSuccess(t *testing.T) {
	deps := baseEnvDeps()
	tracePath := "/tracefs/custom"
	btfPath := "/sys/kernel/btf/vmlinux"
	deps.stat = stubStat(map[string]bool{
		tracePath: true,
		btfPath:   false,
	})
	var lookedUp string
	deps.lookPath = func(name string) (string, error) {
		lookedUp = name
		return "/usr/bin/" + name, nil
	}
	env, err := inspectEBPFEnvironmentWithDeps(map[string]any{
		"tracefs_path": tracePath,
		"btf_path":     btfPath,
		"clang_path":   "clang-15",
	}, deps)
	if err != nil {
		t.Fatalf("inspectEBPFEnvironmentWithDeps: %v", err)
	}
	if env.TraceFSPath != tracePath {
		t.Fatalf("unexpected tracefs path: %s", env.TraceFSPath)
	}
	if env.BTFPath != btfPath {
		t.Fatalf("unexpected btf path: %s", env.BTFPath)
	}
	if env.Target != "bpfel" || env.ArchMacro != "x86" {
		t.Fatalf("unexpected target %s arch %s", env.Target, env.ArchMacro)
	}
	if lookedUp != "clang-15" {
		t.Fatalf("expected clang lookup, got %s", lookedUp)
	}
}

func TestInspectEBPFEnvironmentRejectsOldKernel(t *testing.T) {
	deps := baseEnvDeps()
	deps.kernelVersion = func() (string, int, int, int, error) {
		return "5.4.0", 5, 4, 0, nil
	}
	if _, err := inspectEBPFEnvironmentWithDeps(nil, deps); err == nil || !strings.Contains(err.Error(), "too old") {
		t.Fatalf("expected error for old kernel, got %v", err)
	}
}

func TestInspectEBPFEnvironmentRequiresTraceFSDir(t *testing.T) {
	deps := baseEnvDeps()
	deps.stat = stubStat(map[string]bool{
		"/missing":                false,
		"/sys/kernel/btf/vmlinux": false,
	})
	_, err := inspectEBPFEnvironmentWithDeps(map[string]any{"tracefs_path": "/missing"}, deps)
	if err == nil || !strings.Contains(err.Error(), "tracefs path /missing invalid") {
		t.Fatalf("expected tracefs error, got %v", err)
	}
}

func TestInspectEBPFEnvironmentRequiresClang(t *testing.T) {
	deps := baseEnvDeps()
	deps.lookPath = func(string) (string, error) {
		return "", os.ErrNotExist
	}
	_, err := inspectEBPFEnvironmentWithDeps(map[string]any{"tracefs_path": "/sys/kernel/tracing"}, deps)
	if err == nil || !strings.Contains(err.Error(), "clang not found") {
		t.Fatalf("expected clang error, got %v", err)
	}
}

func TestInspectEBPFEnvironmentRequiresPrivileges(t *testing.T) {
	deps := baseEnvDeps()
	deps.geteuid = func() int { return 1000 }
	deps.readUnprivilegedBPF = func() (bool, error) { return true, nil }
	_, err := inspectEBPFEnvironmentWithDeps(map[string]any{"tracefs_path": "/sys/kernel/tracing"}, deps)
	if err == nil || !strings.Contains(err.Error(), "require root") {
		t.Fatalf("expected privilege error, got %v", err)
	}
}

func TestInspectEBPFEnvironmentRequiresBTFFile(t *testing.T) {
	deps := baseEnvDeps()
	deps.stat = stubStat(map[string]bool{
		"/sys/kernel/btf/vmlinux": true,
	})
	_, err := inspectEBPFEnvironmentWithDeps(nil, deps)
	if err == nil || !strings.Contains(err.Error(), "kernel BTF file") {
		t.Fatalf("expected btf error, got %v", err)
	}
}

func baseEnvDeps() envDeps {
	return envDeps{
		goos:   "linux",
		goarch: "amd64",
		kernelVersion: func() (string, int, int, int, error) {
			return "5.10.0", 5, 10, 0, nil
		},
		detectTraceFS: func() (string, error) {
			return "/sys/kernel/tracing", nil
		},
		stat: stubStat(map[string]bool{
			"/sys/kernel/btf/vmlinux": false,
			"/sys/kernel/tracing":     true,
		}),
		lookPath: func(name string) (string, error) {
			return "/usr/bin/" + name, nil
		},
		geteuid: func() int { return 0 },
		readUnprivilegedBPF: func() (bool, error) {
			return false, nil
		},
	}
}

func stubStat(entries map[string]bool) func(string) (os.FileInfo, error) {
	return func(path string) (os.FileInfo, error) {
		dir, ok := entries[path]
		if !ok {
			return nil, os.ErrNotExist
		}
		return stubFileInfo{dir: dir}, nil
	}
}

type stubFileInfo struct {
	dir bool
}

func (s stubFileInfo) Name() string       { return "" }
func (s stubFileInfo) Size() int64        { return 0 }
func (s stubFileInfo) Mode() os.FileMode  { return 0 }
func (s stubFileInfo) ModTime() time.Time { return time.Time{} }
func (s stubFileInfo) IsDir() bool        { return s.dir }
func (s stubFileInfo) Sys() any           { return nil }
