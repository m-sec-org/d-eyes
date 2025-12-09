//go:build linux

package collector

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// networkEventParser enriches socket/connect events.
type networkEventParser struct{}

func (networkEventParser) Name() string { return "network" }

func (networkEventParser) SupportedEventTypes() []uint32 {
	return []uint32{ebpfEventTypeSocket, ebpfEventTypeConnect, ebpfEventTypeSendmsg}
}

func (networkEventParser) Parse(evt *syscallEvent, sourceName, collectorName string) (*SystemEvent, error) {
	event := buildEBPFSystemEvent(evt, sourceName, collectorName)
	if event.Metadata == nil {
		event.Metadata = make(map[string]string, 2)
	}
	switch evt.EventType {
	case ebpfEventTypeSocket:
		event.Metadata["ebpf.event_kind"] = "net.socket"
		if evt.Extra0 != 0 {
			event.Metadata["socket.family"] = familyName(evt.Extra0)
		}
		if evt.Extra1 != 0 {
			event.Metadata["socket.type"] = fmt.Sprintf("%d", evt.Extra1)
		}
		if evt.Extra2 != 0 {
			event.Metadata["socket.protocol"] = fmt.Sprintf("%d", evt.Extra2)
		}
	case ebpfEventTypeConnect:
		event.Metadata["ebpf.event_kind"] = "net.connect"
		if event.Payload == nil {
			event.Payload = make(map[string]any, 2)
		}
		fd := int32(evt.Aux)
		event.Payload["fd"] = fd
		event.Metadata["socket.fd"] = fmt.Sprintf("%d", fd)
		if evt.Extra0 != 0 {
			event.Metadata["connect.family"] = familyName(evt.Extra0)
		}
		if evt.Extra1 != 0 {
			event.Metadata["connect.port"] = fmt.Sprintf("%d", evt.Extra1)
		}
		if evt.Extra2 != 0 {
			event.Metadata["connect.ipv4"] = formatIPv4(evt.Extra2)
		}
		if evt.Extra3 == connectAddrTagUnix && evt.DataKind == ebpfDataKindString {
			if path := trimCString(evt.Data[:]); path != "" {
				event.Payload["unix_path"] = path
				event.Metadata["connect.unix_path"] = path
			}
		}
		if evt.Extra3 == connectAddrTagIPv6 || (evt.DataKind == ebpfDataKindIPv6 && evt.Extra0 == unix.AF_INET6) {
			if ip := formatIPv6(evt.Data[:], evt.DataLen); ip != "" {
				event.Metadata["connect.ipv6"] = ip
			}
		}
	case ebpfEventTypeSendmsg:
		event.Metadata["ebpf.event_kind"] = "net.sendmsg"
		if event.Payload == nil {
			event.Payload = make(map[string]any, 1)
		}
		fd := int32(evt.Aux)
		event.Payload["fd"] = fd
		event.Metadata["socket.fd"] = fmt.Sprintf("%d", fd)
		if evt.Extra0 != 0 {
			event.Metadata["sendmsg.family"] = familyName(evt.Extra0)
		}
		if evt.Extra1 != 0 {
			event.Metadata["sendmsg.port"] = fmt.Sprintf("%d", evt.Extra1)
		}
		if evt.Extra2 != 0 {
			event.Metadata["sendmsg.ipv4"] = formatIPv4(evt.Extra2)
		}
		if evt.Extra3 == connectAddrTagUnix && evt.DataKind == ebpfDataKindString {
			if path := trimCString(evt.Data[:]); path != "" {
				event.Metadata["sendmsg.unix_path"] = path
				if event.Payload == nil {
					event.Payload = make(map[string]any, 1)
				}
				event.Payload["unix_path"] = path
			}
		}
		if (evt.Extra3 == connectAddrTagIPv6 || evt.DataKind == ebpfDataKindIPv6) && evt.DataLen > 0 {
			if ip := formatIPv6(evt.Data[:], evt.DataLen); ip != "" {
				event.Metadata["sendmsg.ipv6"] = ip
			}
		}
	}
	return event, nil
}

func (networkEventParser) Configure(ParserConfig) error { return nil }
