//go:build linux

package collector

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

const maxProbeAttachAttempts = 3

type probeAttachLog struct {
	Timestamp time.Time
	Probe     string
	Status    string
	Detail    string
}

type programResolver func(symbol string) (*ebpf.Program, error)
type tracepointAttacher func(group, point string, prog *ebpf.Program) (linkHandle, error)

type linkHandle interface {
	Close() error
}

type ebpfProbeManager struct {
	mu       sync.Mutex
	links    map[string]linkHandle
	resolve  programResolver
	attachTP tracepointAttacher
}

func newEBPFProbeManager(resolver programResolver, attacher tracepointAttacher) *ebpfProbeManager {
	if attacher == nil {
		attacher = defaultTracepointAttacher
	}
	return &ebpfProbeManager{
		links:    make(map[string]linkHandle),
		resolve:  resolver,
		attachTP: attacher,
	}
}

func (m *ebpfProbeManager) Apply(probes []ebpfProbe) ([]string, []string, []probeAttachLog, error) {
	if m == nil {
		return nil, nil, nil, errors.New("probe manager not initialised")
	}
	ok := make([]string, 0, len(probes))
	var failed []string
	newLinks := make(map[string]linkHandle, len(probes))
	attachLogs := make([]probeAttachLog, 0, len(probes))
	for _, probe := range probes {
		linkInst, logs, err := m.attachWithRetry(probe)
		attachLogs = append(attachLogs, logs...)
		if err != nil {
			failed = append(failed, fmt.Sprintf("%s/%s (%v)", probe.TraceGroup, probe.TracePoint, err))
			m.closeLinks(newLinks)
			return ok, failed, attachLogs, err
		}
		newLinks[probe.Name] = linkInst
		ok = append(ok, fmt.Sprintf("%s/%s", probe.TraceGroup, probe.TracePoint))
	}
	m.mu.Lock()
	prev := m.links
	m.links = newLinks
	m.mu.Unlock()
	m.closeLinks(prev)
	return ok, failed, attachLogs, nil
}

func (m *ebpfProbeManager) Close() error {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	links := m.links
	m.links = make(map[string]linkHandle)
	m.mu.Unlock()
	return m.closeLinks(links)
}

func (m *ebpfProbeManager) closeLinks(links map[string]linkHandle) error {
	var multi error
	for name, l := range links {
		if l == nil {
			continue
		}
		multi = errors.Join(multi, l.Close())
		delete(links, name)
	}
	return multi
}

func defaultTracepointAttacher(group, point string, prog *ebpf.Program) (linkHandle, error) {
	return link.Tracepoint(group, point, prog, nil)
}

func (m *ebpfProbeManager) attachWithRetry(probe ebpfProbe) (linkHandle, []probeAttachLog, error) {
	prog, err := m.resolve(probe.Program)
	logs := make([]probeAttachLog, 0, maxProbeAttachAttempts)
	if err != nil {
		logs = append(logs, probeAttachLog{
			Timestamp: time.Now(),
			Probe:     probe.Name,
			Status:    "error",
			Detail:    fmt.Sprintf("resolve: %v", err),
		})
		return nil, logs, err
	}
	for attempt := 1; attempt <= maxProbeAttachAttempts; attempt++ {
		linkInst, attachErr := m.attachTP(probe.TraceGroup, probe.TracePoint, prog)
		if attachErr == nil {
			logs = append(logs, probeAttachLog{
				Timestamp: time.Now(),
				Probe:     probe.Name,
				Status:    "attached",
				Detail:    fmt.Sprintf("attempt %d/%d succeeded", attempt, maxProbeAttachAttempts),
			})
			return linkInst, logs, nil
		}
		logs = append(logs, probeAttachLog{
			Timestamp: time.Now(),
			Probe:     probe.Name,
			Status:    "retry",
			Detail:    fmt.Sprintf("attempt %d/%d: %v", attempt, maxProbeAttachAttempts, attachErr),
		})
		if attempt < maxProbeAttachAttempts {
			time.Sleep(25 * time.Millisecond)
			continue
		}
		logs = append(logs, probeAttachLog{
			Timestamp: time.Now(),
			Probe:     probe.Name,
			Status:    "failed",
			Detail:    fmt.Sprintf("attach %s/%s failed: %v", probe.TraceGroup, probe.TracePoint, attachErr),
		})
		return nil, logs, fmt.Errorf("attach %s/%s: %w", probe.TraceGroup, probe.TracePoint, attachErr)
	}
	return nil, logs, fmt.Errorf("attach %s/%s: unknown error", probe.TraceGroup, probe.TracePoint)
}
