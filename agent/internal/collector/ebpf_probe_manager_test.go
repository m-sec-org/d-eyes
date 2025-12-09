//go:build linux

package collector

import (
	"fmt"
	"testing"

	"github.com/cilium/ebpf"
)

type fakeLink struct {
	closed bool
}

func (f *fakeLink) Close() error {
	f.closed = true
	return nil
}

func (f *fakeLink) Detach() error {
	f.closed = true
	return nil
}

func TestProbeManagerApplyAndClose(t *testing.T) {
	var created []*fakeLink
	manager := newEBPFProbeManager(func(string) (*ebpf.Program, error) {
		return &ebpf.Program{}, nil
	}, func(group, point string, prog *ebpf.Program) (linkHandle, error) {
		l := &fakeLink{}
		created = append(created, l)
		return l, nil
	})
	ok, fail, logs, err := manager.Apply([]ebpfProbe{
		{Name: "a", TraceGroup: "syscalls", TracePoint: "sys_enter_execve", Program: "handle_sys_enter_execve"},
	})
	if err != nil || len(fail) != 0 || len(ok) != 1 {
		t.Fatalf("expected probe attach success, got ok=%v fail=%v err=%v", ok, fail, err)
	}
	if len(logs) == 0 || logs[len(logs)-1].Status != "attached" {
		t.Fatalf("expected attach log on success, got %#v", logs)
	}
	if len(created) != 1 {
		t.Fatalf("expected 1 link, got %d", len(created))
	}
	if err := manager.Close(); err != nil {
		t.Fatalf("manager close: %v", err)
	}
	if !created[0].closed {
		t.Fatalf("expected link to be closed")
	}
}

func TestProbeManagerFailureKeepsPreviousLinks(t *testing.T) {
	var created []*fakeLink
	resolver := func(symbol string) (*ebpf.Program, error) {
		if symbol == "fail" {
			return nil, fmt.Errorf("resolver error")
		}
		return &ebpf.Program{}, nil
	}
	manager := newEBPFProbeManager(resolver, func(group, point string, prog *ebpf.Program) (linkHandle, error) {
		l := &fakeLink{}
		created = append(created, l)
		return l, nil
	})
	if _, _, _, err := manager.Apply([]ebpfProbe{
		{Name: "exec", TraceGroup: "syscalls", TracePoint: "sys_enter_execve", Program: "good"},
	}); err != nil {
		t.Fatalf("first apply: %v", err)
	}
	_, _, logs, err := manager.Apply([]ebpfProbe{
		{Name: "exec", TraceGroup: "syscalls", TracePoint: "sys_enter_execve", Program: "fail"},
	})
	if err == nil {
		t.Fatalf("expected error when resolver fails")
	}
	if len(logs) == 0 || logs[len(logs)-1].Status != "error" {
		t.Fatalf("expected error log, got %#v", logs)
	}
	// Previously attached link should still be open.
	if len(created) != 1 {
		t.Fatalf("expected only original link to be created")
	}
	if created[0].closed {
		t.Fatalf("expected original link to remain open on failure")
	}
}
