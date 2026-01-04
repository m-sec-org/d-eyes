//go:build linux

package collector

import (
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestTrojanUploadDetectorConnectThenWrite(t *testing.T) {
	engine := newEBPFDetectionEngine()
	connect := &SystemEvent{
		EventType: "net.connect",
		Metadata: map[string]string{
			"connect.port": "8080",
			"connect.ipv4": "203.0.113.10",
		},
		Payload: map[string]any{
			"pid":  uint32(1234),
			"comm": "curl",
		},
		Timestamp: time.Now(),
	}
	if res := engine.Evaluate(connect); res != nil {
		t.Fatalf("expected no detection on connect alone, got %#v", res)
	}
	write := &SystemEvent{
		EventType: "fs.write",
		Metadata:  map[string]string{},
		Payload: map[string]any{
			"pid":  uint32(1234),
			"path": "/tmp/.cache/payload.bin",
		},
		Timestamp: time.Now().Add(2 * time.Second),
	}
	res := engine.Evaluate(write)
	if res == nil {
		t.Fatalf("expected trojan upload detection")
	}
	if res.Category != "trojan_upload" {
		t.Fatalf("unexpected category %s", res.Category)
	}
}

func TestMemoryImplantDetectorTriggersOnWriteExec(t *testing.T) {
	engine := newEBPFDetectionEngine()
	event := &SystemEvent{
		EventType: "mem.mprotect",
		Payload: map[string]any{
			"pid":     uint32(4321),
			"prot":    uint64(unix.PROT_WRITE | unix.PROT_EXEC),
			"address": uint64(0x1000),
			"length":  uint64(0x2000),
		},
		Timestamp: time.Now(),
	}
	res := engine.Evaluate(event)
	if res == nil {
		t.Fatalf("expected memory implant detection")
	}
	if res.Category != "memory_implant" {
		t.Fatalf("unexpected category %s", res.Category)
	}
}

func TestRemoteCommandDetectorConnectThenShell(t *testing.T) {
	engine := newEBPFDetectionEngine()
	connect := &SystemEvent{
		EventType: "net.connect",
		Metadata: map[string]string{
			"connect.port": "22",
			"connect.ipv4": "198.51.100.3",
		},
		Payload: map[string]any{
			"pid": uint32(777),
		},
		Timestamp: time.Now(),
	}
	engine.Evaluate(connect)
	exec := &SystemEvent{
		EventType: "process.exec",
		Payload: map[string]any{
			"pid":  uint32(777),
			"path": "/bin/bash",
		},
		Timestamp: time.Now().Add(5 * time.Second),
	}
	res := engine.Evaluate(exec)
	if res == nil {
		t.Fatalf("expected remote command detection")
	}
	if res.Category != "remote_command" {
		t.Fatalf("unexpected category %s", res.Category)
	}
}
