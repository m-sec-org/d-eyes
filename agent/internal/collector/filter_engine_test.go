package collector

import "testing"

func TestRuleFilterEngineIncludeExclude(t *testing.T) {
	engine := newRuleFilterEngine(Filters{
		Include: map[string][]string{
			"source": {"windows.security"},
		},
		Exclude: map[string][]string{
			"event_type": {"windows.security.logoff"},
		},
	})
	event := &SystemEvent{
		Source:    "windows.security",
		EventType: "windows.security.logon",
	}
	if !engine.ShouldProcess(event) {
		t.Fatalf("expected logon event to pass include filters")
	}
	event.EventType = "windows.security.logoff"
	if engine.ShouldProcess(event) {
		t.Fatalf("expected logoff event to be excluded by exclude filters")
	}
}

func TestRuleFilterEngineDropRule(t *testing.T) {
	engine := newRuleFilterEngine(Filters{
		Rules: []FilterRule{
			{
				Name:    "drop-informational",
				Action:  "drop",
				Enabled: true,
				Conditions: []FilterCondition{
					{Field: "metadata.severity", Operator: "equals", Value: "info"},
				},
			},
		},
	})
	event := &SystemEvent{
		EventType: "windows.security.logon",
		Metadata: map[string]string{
			"severity": "info",
		},
	}
	if engine.ShouldProcess(event) {
		t.Fatalf("expected info severity event to be dropped by rule")
	}
	stats := engine.Stats()
	if stats.Dropped == 0 || stats.Evaluated == 0 {
		t.Fatalf("expected stats to reflect evaluation %+v", stats)
	}
	event.Metadata["severity"] = "warning"
	if !engine.ShouldProcess(event) {
		t.Fatalf("warning severity should not be dropped")
	}
}

func TestRuleFilterEngineUpdateConfig(t *testing.T) {
	engine := newRuleFilterEngine(Filters{})
	event := &SystemEvent{
		EventType: "windows.system.event",
		Metadata: map[string]string{
			"severity": "critical",
		},
	}
	if !engine.ShouldProcess(event) {
		t.Fatalf("event should pass with empty config")
	}
	err := engine.UpdateConfig(Filters{
		Include: map[string][]string{"event_type": {"windows.system.event"}},
		Rules: []FilterRule{
			{
				Name:    "drop-critical",
				Action:  "drop",
				Enabled: true,
				Conditions: []FilterCondition{
					{Field: "metadata.severity", Operator: "equals", Value: "critical"},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("update config failed: %v", err)
	}
	if engine.ShouldProcess(event) {
		t.Fatalf("event should now be dropped by updated config")
	}
}
