package collector

import (
	"fmt"
	"strings"
	"time"
)

type detector interface {
	ID() string
	Name() string
	Evaluate(event *SystemEvent) *DetectionResult
}

type detectionEngine struct {
	detectors []detector
	stats     detectionStats
}

func newDetectionEngine() *detectionEngine {
	return &detectionEngine{
		detectors: []detector{
			defenderThreatDetector{},
			serviceInstallDetector{},
			criticalProcessDetector{},
			containerEscapeDetector{},
		},
	}
}

func (e *detectionEngine) Evaluate(event *SystemEvent) *DetectionResult {
	if e == nil || event == nil {
		return nil
	}
	for _, det := range e.detectors {
		result := det.Evaluate(event)
		if result == nil {
			continue
		}
		if result.RuleID == "" {
			result.RuleID = det.ID()
		}
		if result.Name == "" {
			result.Name = det.Name()
		}
		if result.ID == "" {
			result.ID = fmt.Sprintf("%s-%d", result.RuleID, time.Now().UnixNano())
		}
		e.stats.Record(result.RuleID, result.ID)
		return result
	}
	return nil
}

func (e *detectionEngine) Stats() (uint64, map[string]uint64, map[string]string) {
	if e == nil {
		return 0, nil, nil
	}
	return e.stats.Snapshot()
}

type defenderThreatDetector struct{}

func (defenderThreatDetector) ID() string   { return "windows.defender.threat" }
func (defenderThreatDetector) Name() string { return "Windows Defender Threat" }

func (defenderThreatDetector) Evaluate(event *SystemEvent) *DetectionResult {
	if event == nil {
		return nil
	}
	if !strings.HasPrefix(event.Source, "windows.defender") {
		return nil
	}
	switch event.EventType {
	case "windows.defender.threat.detected", "windows.defender.quarantine":
	default:
		return nil
	}
	severity := "medium"
	if event.Metadata != nil && event.Metadata["severity"] != "" {
		severity = event.Metadata["severity"]
	}
	meta := map[string]string{
		"event_type": event.EventType,
		"source":     event.Source,
	}
	for k, v := range event.Metadata {
		if strings.HasPrefix(k, "threat") || strings.HasPrefix(k, "provider") {
			meta[k] = v
		}
	}
	return &DetectionResult{
		RuleID:         "detector.trojan.upload",
		Name:           "Defender Threat Detected",
		Category:       "trojan_upload",
		Severity:       severity,
		Action:         DetectionActionRespond,
		Description:    "Windows Defender reported a high severity threat.",
		Confidence:     0.9,
		RespondProfile: "quick",
		Metadata:       meta,
		Tags: map[string]string{
			"threat_source": "defender",
		},
	}
}

type serviceInstallDetector struct{}

func (serviceInstallDetector) ID() string   { return "windows.system.service.install" }
func (serviceInstallDetector) Name() string { return "Suspicious Service Install" }

func (serviceInstallDetector) Evaluate(event *SystemEvent) *DetectionResult {
	if event == nil {
		return nil
	}
	if event.EventType != "windows.system.service.install" {
		return nil
	}
	return &DetectionResult{
		RuleID:      "detector.remote.command",
		Name:        "New Service Installed",
		Category:    "remote_command",
		Severity:    "high",
		Action:      DetectionActionRespond,
		Description: "Unexpected service installation may indicate remote command execution.",
		Confidence:  0.75,
		Metadata: map[string]string{
			"provider": event.Metadata["provider"],
			"channel":  event.Metadata["channel"],
		},
		RespondProfile: "quick",
	}
}

type criticalProcessDetector struct{}

func (criticalProcessDetector) ID() string   { return "windows.security.process" }
func (criticalProcessDetector) Name() string { return "Critical Process Execution" }

func (criticalProcessDetector) Evaluate(event *SystemEvent) *DetectionResult {
	if event == nil {
		return nil
	}
	if event.EventType != "windows.security.process.create" {
		return nil
	}
	if strings.ToLower(event.Metadata["severity"]) != "critical" {
		return nil
	}
	return &DetectionResult{
		RuleID:         "detector.memory.implant",
		Name:           "Critical Process Spawn",
		Category:       "memory_implant",
		Severity:       "critical",
		Action:         DetectionActionRespond,
		Description:    "A critical severity process creation event was observed.",
		Confidence:     0.72,
		RespondProfile: "quick",
	}
}

type containerEscapeDetector struct{}

func (containerEscapeDetector) ID() string   { return "windows.container.escape" }
func (containerEscapeDetector) Name() string { return "Container Escape Attempt" }

func (containerEscapeDetector) Evaluate(event *SystemEvent) *DetectionResult {
	if event == nil {
		return nil
	}
	if !strings.HasPrefix(event.Source, "windows.container") {
		return nil
	}
	if event.EventType != "windows.container.image.pull" && event.EventType != "windows.container.start" {
		return nil
	}
	return &DetectionResult{
		RuleID:      "detector.container.exfil",
		Name:        "Container Activity",
		Category:    "container",
		Severity:    "medium",
		Action:      DetectionActionAlert,
		Description: "Container lifecycle event recorded for observability.",
		Confidence:  0.55,
		Metadata: map[string]string{
			"channel": event.Metadata["channel"],
		},
	}
}
