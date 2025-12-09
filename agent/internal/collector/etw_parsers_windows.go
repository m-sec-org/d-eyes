//go:build windows

package collector

import (
	"fmt"
	"strings"
)

var (
	securityEventMap = map[uint16]string{
		4624: "windows.security.logon",
		4625: "windows.security.logon.failed",
		4634: "windows.security.logoff",
		4648: "windows.security.logon.explicit",
		4672: "windows.security.privilege.assigned",
		4688: "windows.security.process.create",
		4689: "windows.security.process.exit",
		4698: "windows.security.task.schedule.create",
	}
	systemEventMap = map[uint16]string{
		6005: "windows.system.eventlog.start",
		6006: "windows.system.eventlog.stop",
		6008: "windows.system.unexpected_shutdown",
		7036: "windows.system.service.state_change",
		7045: "windows.system.service.install",
	}
	applicationEventMap = map[uint16]string{
		1000: "windows.application.error",
		1001: "windows.application.hang",
		1002: "windows.application.recovery",
	}
	defenderEventMap = map[uint16]string{
		1116: "windows.defender.threat.detected",
		1117: "windows.defender.action.taken",
		1118: "windows.defender.quarantine",
		5001: "windows.defender.service.started",
		5004: "windows.defender.signature.updated",
	}
	containerEventMap = map[uint16]string{
		1030: "windows.container.create",
		1031: "windows.container.start",
		1032: "windows.container.stop",
		1050: "windows.container.image.pull",
	}
)

type securityEventParser struct{}

func (securityEventParser) Name() string { return "security" }

func (securityEventParser) SupportedProviders() []string {
	return []string{providerSecurityGUID}
}

func (securityEventParser) ParseEvent(record *eventRecord) (*SystemEvent, error) {
	return buildEventFromRecord(record, "windows.security", "windows.security.event", securityEventMap, map[string]string{
		"channel":  "security",
		"provider": "microsoft-windows-security-auditing",
	}, map[string]string{
		"category": "security",
	})
}

func (securityEventParser) Configure(ParserConfig) error { return nil }

type systemEventParser struct{}

func (systemEventParser) Name() string { return "system" }

func (systemEventParser) SupportedProviders() []string {
	return []string{providerSystemGUID}
}

func (systemEventParser) ParseEvent(record *eventRecord) (*SystemEvent, error) {
	return buildEventFromRecord(record, "windows.system", "windows.system.event", systemEventMap, map[string]string{
		"channel":  "system",
		"provider": "microsoft-windows-system",
	}, map[string]string{
		"category": "platform",
	})
}

func (systemEventParser) Configure(ParserConfig) error { return nil }

type applicationEventParser struct{}

func (applicationEventParser) Name() string { return "application" }

func (applicationEventParser) SupportedProviders() []string {
	return []string{providerApplicationGUID}
}

func (applicationEventParser) ParseEvent(record *eventRecord) (*SystemEvent, error) {
	return buildEventFromRecord(record, "windows.application", "windows.application.event", applicationEventMap, map[string]string{
		"channel":  "application",
		"provider": "microsoft-windows-application",
	}, map[string]string{
		"category": "application",
	})
}

func (applicationEventParser) Configure(ParserConfig) error { return nil }

type defenderEventParser struct{}

func (defenderEventParser) Name() string { return "defender" }

func (defenderEventParser) SupportedProviders() []string {
	return []string{providerDefenderGUID}
}

func (defenderEventParser) ParseEvent(record *eventRecord) (*SystemEvent, error) {
	event, err := buildEventFromRecord(record, "windows.defender", "windows.defender.event", defenderEventMap, map[string]string{
		"channel":  "security",
		"provider": "microsoft-windows-defender",
	}, map[string]string{
		"category": "defender",
	})
	if event != nil && event.Tags != nil {
		event.Tags["threat_source"] = "defender"
	}
	return event, err
}

func (defenderEventParser) Configure(ParserConfig) error { return nil }

type containerEventParser struct{}

func (containerEventParser) Name() string { return "container" }

func (containerEventParser) SupportedProviders() []string {
	return []string{providerContainerGUID}
}

func (containerEventParser) ParseEvent(record *eventRecord) (*SystemEvent, error) {
	return buildEventFromRecord(record, "windows.container", "windows.container.event", containerEventMap, map[string]string{
		"channel":  "microsoft-windows-container",
		"provider": "microsoft-windows-container",
	}, map[string]string{
		"category": "container",
	})
}

func (containerEventParser) Configure(ParserConfig) error { return nil }

func buildEventFromRecord(record *eventRecord, source, defaultPrefix string, mapping map[uint16]string, metadata map[string]string, tags map[string]string) (*SystemEvent, error) {
	if record == nil {
		return nil, nil
	}
	event := convertEventRecord(record)
	if event == nil {
		return nil, nil
	}
	event.Source = source
	event.EventType = resolveEventType(record.EventHeader.EventDescriptor.Id, defaultPrefix, mapping)
	levelName := severityFromLevel(record.EventHeader.EventDescriptor.Level)
	if event.Metadata == nil {
		event.Metadata = make(map[string]string)
	}
	event.Metadata["severity"] = levelName
	event.Metadata["provider_guid"] = strings.ToLower(record.EventHeader.ProviderId.String())
	for k, v := range metadata {
		event.Metadata[k] = v
	}
	if event.Payload == nil {
		event.Payload = make(map[string]any)
	}
	event.Payload["event_id"] = int(record.EventHeader.EventDescriptor.Id)
	event.Payload["version"] = int(record.EventHeader.EventDescriptor.Version)
	event.Payload["keyword"] = record.EventHeader.EventDescriptor.Keyword
	if event.Tags == nil {
		event.Tags = make(map[string]string)
	}
	for k, v := range tags {
		event.Tags[k] = v
	}
	event.Tags["channel"] = metadata["channel"]
	return event, nil
}

func resolveEventType(eventID uint16, prefix string, mapping map[uint16]string) string {
	if value, ok := mapping[eventID]; ok && value != "" {
		return value
	}
	return fmt.Sprintf("%s.%d", prefix, eventID)
}

func severityFromLevel(level uint8) string {
	switch level {
	case 1:
		return "critical"
	case 2:
		return "error"
	case 3:
		return "warning"
	case 4:
		return "info"
	default:
		return "verbose"
	}
}
