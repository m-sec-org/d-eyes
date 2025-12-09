//go:build linux

package collector

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

type memoryEventParser struct{}

type memoryEventPayload struct {
	Addr   uint64
	Len    uint64
	Prot   uint64
	Flags  uint64
	FD     int64
	Offset uint64
}

func (memoryEventParser) Name() string { return "memory" }

func (memoryEventParser) SupportedEventTypes() []uint32 {
	return []uint32{ebpfEventTypeMMap, ebpfEventTypeMProtect, ebpfEventTypeMUnmap}
}

func (memoryEventParser) Parse(evt *syscallEvent, sourceName, collectorName string) (*SystemEvent, error) {
	event := buildEBPFSystemEvent(evt, sourceName, collectorName)
	if event.Metadata == nil {
		event.Metadata = make(map[string]string, 2)
	}
	if event.Payload == nil {
		event.Payload = make(map[string]any, 4)
	}
	payload, ok := decodeMemoryPayload(evt)
	switch evt.EventType {
	case ebpfEventTypeMMap:
		event.Metadata["ebpf.event_kind"] = "mem.mmap"
	case ebpfEventTypeMProtect:
		event.Metadata["ebpf.event_kind"] = "mem.mprotect"
	case ebpfEventTypeMUnmap:
		event.Metadata["ebpf.event_kind"] = "mem.munmap"
	}
	if ok {
		event.Payload["address"] = payload.Addr
		event.Payload["length"] = payload.Len
		if payload.Prot != 0 {
			event.Payload["prot"] = payload.Prot
			event.Metadata["memory.prot"] = fmt.Sprintf("0x%x", payload.Prot)
		}
		if payload.Flags != 0 {
			event.Payload["flags"] = payload.Flags
			event.Metadata["memory.flags"] = fmt.Sprintf("0x%x", payload.Flags)
		}
		if payload.FD != 0 {
			event.Payload["fd"] = payload.FD
		}
		if payload.Offset != 0 {
			event.Payload["offset"] = payload.Offset
		}
	}
	return event, nil
}

func (memoryEventParser) Configure(ParserConfig) error { return nil }

func decodeMemoryPayload(evt *syscallEvent) (memoryEventPayload, bool) {
	var payload memoryEventPayload
	if evt == nil || evt.DataKind != ebpfDataKindBinary {
		return payload, false
	}
	length := int(evt.DataLen)
	if length <= 0 || length > len(evt.Data) {
		length = len(evt.Data)
	}
	reader := bytes.NewReader(evt.Data[:length])
	if err := binary.Read(reader, binary.LittleEndian, &payload); err != nil {
		return memoryEventPayload{}, false
	}
	return payload, true
}
