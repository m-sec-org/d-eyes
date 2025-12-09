package collector

import "testing"

func TestDefenderThreatDetector(t *testing.T) {
	engine := newDetectionEngine()
	event := &SystemEvent{
		Source:    "windows.defender",
		EventType: "windows.defender.threat.detected",
		Metadata:  map[string]string{"severity": "critical"},
	}
	result := engine.Evaluate(event)
	if result == nil {
		t.Fatalf("expected detection result")
	}
	if result.Action != DetectionActionRespond {
		t.Fatalf("expected respond action, got %s", result.Action)
	}
	if result.RuleID == "" || result.Name == "" {
		t.Fatalf("expected rule metadata")
	}
	total, perRule, _ := engine.Stats()
	if total == 0 || len(perRule) == 0 {
		t.Fatalf("expected stats to be recorded")
	}
}

func TestServiceInstallDetector(t *testing.T) {
	engine := newDetectionEngine()
	event := &SystemEvent{
		Source:    "windows.system",
		EventType: "windows.system.service.install",
		Metadata:  map[string]string{"channel": "system"},
	}
	result := engine.Evaluate(event)
	if result == nil {
		t.Fatalf("expected detection result for service install")
	}
	if result.Category != "remote_command" {
		t.Fatalf("unexpected category %s", result.Category)
	}
}
