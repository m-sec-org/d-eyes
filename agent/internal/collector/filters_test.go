package collector

import "testing"

func TestFilterMatchesAllSupportsMetadataAndTags(t *testing.T) {
	event := &SystemEvent{
		EventType: "process.exec",
		Source:    "ebpf-default",
		Metadata: map[string]string{
			"Collector": "Diag-EBPF",
			"backend":   "ebpf",
		},
		Tags: map[string]string{
			"ENV": "prod",
		},
	}
	include := map[string][]string{
		"event_type": {"process.exec"},
		"collector":  {"diag-ebpf"},
		"env":        {"prod"},
	}
	if !filterMatchesAll(include, event) {
		t.Fatalf("expected include filters to match event")
	}
	event.Tags["env"] = "staging"
	if filterMatchesAll(include, event) {
		t.Fatalf("expected include filters to fail after tag change")
	}
}

func TestFilterMatchesAnyExcludesOnCaseInsensitiveMetadata(t *testing.T) {
	event := &SystemEvent{
		EventType: "process.exit",
		Source:    "etw-provider",
		Metadata: map[string]string{
			"LEVEL": "4",
		},
	}
	if filterMatchesAny(nil, event) {
		t.Fatalf("nil filters should not match")
	}
	exclude := map[string][]string{
		"level": {"4"},
		"source": {
			"something-else",
		},
	}
	if !filterMatchesAny(exclude, event) {
		t.Fatalf("expected exclude filters to match metadata")
	}
	exclude["level"] = []string{"5"}
	if filterMatchesAny(exclude, event) {
		t.Fatalf("unexpected match with non-existent metadata")
	}
}
