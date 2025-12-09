//go:build linux

package collector

import (
	"fmt"
	"time"
)

type defaultEBPFParser struct{}

func (defaultEBPFParser) Name() string { return "default" }

func (defaultEBPFParser) SupportedEventTypes() []uint32 { return nil }

func (defaultEBPFParser) Parse(evt *syscallEvent, sourceName, collectorName string) (*SystemEvent, error) {
	if evt == nil {
		return nil, fmt.Errorf("nil ebpf event")
	}
	event := buildEBPFSystemEvent(evt, sourceName, collectorName)
	return event, nil
}

func (defaultEBPFParser) Configure(ParserConfig) error { return nil }

type execEventParser struct{}

func (execEventParser) Name() string { return "process-exec" }

func (execEventParser) SupportedEventTypes() []uint32 { return []uint32{ebpfEventTypeExec} }

func (execEventParser) Parse(evt *syscallEvent, sourceName, collectorName string) (*SystemEvent, error) {
	event := buildEBPFSystemEvent(evt, sourceName, collectorName)
	if event.Metadata == nil {
		event.Metadata = make(map[string]string, 2)
	}
	event.Metadata["ebpf.event_kind"] = "exec"
	if evt.DataKind == ebpfDataKindString {
		if path := trimCString(evt.Data[:]); path != "" {
			if event.Payload == nil {
				event.Payload = make(map[string]any, 1)
			}
			event.Payload["path"] = path
			event.Metadata["process.exec.path"] = path
		}
	}
	return event, nil
}

func (execEventParser) Configure(ParserConfig) error { return nil }

func buildEBPFSystemEvent(evt *syscallEvent, sourceName, collectorName string) *SystemEvent {
	payload := map[string]any{
		"pid":                 evt.PID,
		"tgid":                evt.TGID,
		"comm":                trimCString(evt.Comm[:]),
		"aux":                 evt.Aux,
		"event_code":          evt.EventType,
		"kernel_timestamp_ns": evt.Timestamp,
		"uid":                 evt.UID,
		"gid":                 evt.GID,
		"cgroup_id":           evt.CgroupID,
	}
	metadata := map[string]string{
		"backend":     "ebpf",
		"collector":   collectorName,
		"process.uid": fmt.Sprintf("%d", evt.UID),
		"process.gid": fmt.Sprintf("%d", evt.GID),
	}
	if evt.CgroupID != 0 {
		metadata["process.cgroup"] = fmt.Sprintf("%d", evt.CgroupID)
	}
	return &SystemEvent{
		Timestamp: time.Now(),
		EventType: ebpfEventTypeName(evt.EventType),
		Source:    sourceName,
		Payload:   payload,
		Metadata:  metadata,
	}
}
