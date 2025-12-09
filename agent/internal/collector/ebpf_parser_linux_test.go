//go:build linux

package collector

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"

	"golang.org/x/sys/unix"
)

func TestEBPFParserManagerRespectsEnabledParsers(t *testing.T) {
	cfg := ParserConfig{
		Enabled: []string{"process-exec"},
	}
	mgr := newEBPFParserManager(cfg)
	mgr.RegisterParser(defaultEBPFParser{})
	mgr.RegisterParser(execEventParser{})
	raw := syscallEvent{EventType: ebpfEventTypeExec, PID: 1, TGID: 2}
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.LittleEndian, raw); err != nil {
		t.Fatalf("binary.Write: %v", err)
	}
	event, _, err := mgr.Parse(buf.Bytes(), "src", "collector")
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	if event.Metadata["ebpf.event_kind"] != "exec" {
		t.Fatalf("expected exec parser metadata, got %+v", event.Metadata)
	}
}

func TestEBPFParserManagerDisablesParser(t *testing.T) {
	cfg := ParserConfig{
		Disabled: []string{"process-exec"},
	}
	mgr := newEBPFParserManager(cfg)
	mgr.RegisterParser(defaultEBPFParser{})
	mgr.RegisterParser(execEventParser{})
	raw := syscallEvent{EventType: ebpfEventTypeExec, PID: 1, TGID: 2}
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.LittleEndian, raw); err != nil {
		t.Fatalf("binary.Write: %v", err)
	}
	event, _, err := mgr.Parse(buf.Bytes(), "src", "collector")
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	if _, ok := event.Metadata["ebpf.event_kind"]; ok {
		t.Fatalf("expected default parser, got metadata %+v", event.Metadata)
	}
}

func TestFileEventParserAddsPath(t *testing.T) {
	parser := fileEventParser{}
	raw := &syscallEvent{
		EventType: ebpfEventTypeOpen,
	}
	copy(raw.Data[:], []byte("test-file.txt"))
	event, err := parser.Parse(raw, "src", "collector")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if event.Payload["path"] != "test-file.txt" {
		t.Fatalf("expected path enrichment, got %+v", event.Payload)
	}
}

func TestNetworkEventParserAddsPort(t *testing.T) {
	parser := networkEventParser{}
	raw := &syscallEvent{
		EventType: ebpfEventTypeConnect,
		Extra0:    unix.AF_INET,
		Extra1:    443,
		Extra2:    binary.BigEndian.Uint32([]byte{127, 0, 0, 1}),
	}
	event, err := parser.Parse(raw, "src", "collector")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if event.Metadata["connect.port"] != "443" {
		t.Fatalf("expected port metadata, got %+v", event.Metadata)
	}
	if event.Metadata["connect.ipv4"] != "127.0.0.1" {
		t.Fatalf("expected ipv4 metadata, got %+v", event.Metadata)
	}
}

func TestNetworkEventParserAddsUnixPath(t *testing.T) {
	parser := networkEventParser{}
	raw := &syscallEvent{
		EventType: ebpfEventTypeConnect,
		Extra0:    unix.AF_UNIX,
		Extra3:    connectAddrTagUnix,
		DataKind:  ebpfDataKindString,
	}
	path := "/tmp/agent.sock"
	copy(raw.Data[:], []byte(path))
	event, err := parser.Parse(raw, "src", "collector")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if event.Payload["unix_path"] != path {
		t.Fatalf("expected unix path payload, got %+v", event.Payload)
	}
	if event.Metadata["connect.unix_path"] != path {
		t.Fatalf("expected unix path metadata, got %+v", event.Metadata)
	}
}

func TestNetworkEventParserAddsIPv6(t *testing.T) {
	parser := networkEventParser{}
	ip := net.ParseIP("2001:db8::1").To16()
	if ip == nil {
		t.Fatalf("failed to parse ipv6")
	}
	raw := &syscallEvent{
		EventType: ebpfEventTypeConnect,
		Extra0:    unix.AF_INET6,
		Extra1:    8443,
		Extra3:    connectAddrTagIPv6,
		DataKind:  ebpfDataKindIPv6,
		DataLen:   uint32(len(ip)),
	}
	copy(raw.Data[:], ip)
	event, err := parser.Parse(raw, "src", "collector")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if event.Metadata["connect.ipv6"] != "2001:db8::1" {
		t.Fatalf("expected ipv6 metadata, got %+v", event.Metadata)
	}
}

func TestMemoryEventParserParsesPayload(t *testing.T) {
	parser := memoryEventParser{}
	payload := memoryEventPayload{
		Addr:   0x1000,
		Len:    0x2000,
		Prot:   0x3,
		Flags:  0x22,
		FD:     5,
		Offset: 0x40,
	}
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.LittleEndian, payload); err != nil {
		t.Fatalf("binary.Write: %v", err)
	}
	raw := &syscallEvent{
		EventType: ebpfEventTypeMMap,
		DataKind:  ebpfDataKindBinary,
		DataLen:   uint32(buf.Len()),
	}
	copy(raw.Data[:], buf.Bytes())
	event, err := parser.Parse(raw, "src", "collector")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if event.Metadata["ebpf.event_kind"] != "mem.mmap" {
		t.Fatalf("expected mem.mmap metadata, got %+v", event.Metadata)
	}
	if addr, ok := event.Payload["address"].(uint64); !ok || addr != payload.Addr {
		t.Fatalf("unexpected address payload: %+v", event.Payload["address"])
	}
	if prot, ok := event.Metadata["memory.prot"]; !ok || prot == "" {
		t.Fatalf("expected memory prot metadata, got %+v", event.Metadata)
	}
}
