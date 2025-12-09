//go:build linux

package collector

import "fmt"

// fileEventParser enriches filesystem events.
type fileEventParser struct{}

func (fileEventParser) Name() string { return "filesystem" }

func (fileEventParser) SupportedEventTypes() []uint32 {
	return []uint32{ebpfEventTypeOpen, ebpfEventTypeWrite, ebpfEventTypeUnlink, ebpfEventTypeRename}
}

func (fileEventParser) Parse(evt *syscallEvent, sourceName, collectorName string) (*SystemEvent, error) {
	event := buildEBPFSystemEvent(evt, sourceName, collectorName)
	if event.Metadata == nil {
		event.Metadata = make(map[string]string, 2)
	}
	switch evt.EventType {
	case ebpfEventTypeOpen:
		event.Metadata["ebpf.event_kind"] = "fs.open"
		if evt.Extra0 != 0 {
			event.Metadata["fs.open.flags"] = fmt.Sprintf("0x%x", evt.Extra0)
		}
		if evt.Extra1 != 0 {
			event.Metadata["fs.open.mode"] = fmt.Sprintf("0%o", evt.Extra1)
		}
		if event.Payload == nil {
			event.Payload = make(map[string]any, 2)
		}
		dirfd := int32(evt.Aux)
		event.Payload["dirfd"] = dirfd
		event.Metadata["fs.open.dirfd"] = fmt.Sprintf("%d", dirfd)
	case ebpfEventTypeWrite:
		event.Metadata["ebpf.event_kind"] = "fs.write"
		if event.Payload == nil {
			event.Payload = make(map[string]any, 2)
		}
		event.Payload["fd"] = int32(evt.Extra0)
		event.Payload["count"] = evt.Extra1
		event.Metadata["fs.write.fd"] = fmt.Sprintf("%d", int32(evt.Extra0))
		event.Metadata["fs.write.count"] = fmt.Sprintf("%d", evt.Extra1)
	case ebpfEventTypeUnlink:
		event.Metadata["ebpf.event_kind"] = "fs.unlink"
		if event.Payload == nil {
			event.Payload = make(map[string]any, 1)
		}
		event.Payload["dirfd"] = int32(evt.Aux)
		event.Metadata["fs.unlink.dirfd"] = fmt.Sprintf("%d", int32(evt.Aux))
	case ebpfEventTypeRename:
		event.Metadata["ebpf.event_kind"] = "fs.rename"
		event.Metadata["fs.rename.old_dirfd"] = fmt.Sprintf("%d", int32(evt.Extra0))
		event.Metadata["fs.rename.new_dirfd"] = fmt.Sprintf("%d", int32(evt.Extra1))
	}
	if evt.EventType == ebpfEventTypeRename && evt.DataKind == ebpfDataKindBinary {
		parseRenamePayload(evt, event)
	} else if path := trimCString(evt.Data[:]); path != "" {
		if event.Payload == nil {
			event.Payload = make(map[string]any, 1)
		}
		event.Payload["path"] = path
	}
	return event, nil
}

func (fileEventParser) Configure(ParserConfig) error { return nil }

func parseRenamePayload(evt *syscallEvent, event *SystemEvent) {
	if evt == nil || event == nil {
		return
	}
	const segment = len(evt.Data) / 2
	oldPath := trimCString(evt.Data[:segment])
	newPath := trimCString(evt.Data[segment:])
	if oldPath == "" && newPath == "" {
		return
	}
	if event.Payload == nil {
		event.Payload = make(map[string]any, 2)
	}
	if oldPath != "" {
		event.Payload["old_path"] = oldPath
	}
	if newPath != "" {
		event.Payload["new_path"] = newPath
	}
}
