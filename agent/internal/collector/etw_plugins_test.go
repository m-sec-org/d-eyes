//go:build windows

package collector

import "testing"

func TestPluginLoaderRegistersParserAndProcessor(t *testing.T) {
	loader := newETWPluginLoader()
	cfgs := []ParserPluginConfig{
		{
			Name:    "custom-container",
			Enabled: true,
			Type:    "parser",
			Metadata: map[string]string{
				"provider":     "{aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}",
				"event_prefix": "windows.custom",
			},
		},
		{
			Name:    "powershell-processor",
			Enabled: true,
			Type:    "processor",
			Config: map[string]any{
				"patterns": []string{"powershell", "certutil"},
			},
		},
	}
	parsers, processors, names, err := loader.Load(cfgs)
	if err != nil {
		t.Fatalf("load plugins: %v", err)
	}
	if len(parsers) != 1 {
		t.Fatalf("expected one parser plugin, got %d", len(parsers))
	}
	if len(processors) != 1 {
		t.Fatalf("expected one processor plugin, got %d", len(processors))
	}
	if len(names) != 2 {
		t.Fatalf("expected two plugin names, got %d", len(names))
	}
	event := &SystemEvent{Payload: map[string]any{"user_data_hex": "706f7765727368656c6c"}}
	if _, err := processors[0].Process(nil, event); err != nil {
		t.Fatalf("processor failed: %v", err)
	}
	if event.Metadata["suspicious.command"] == "" {
		t.Fatalf("expected processor to annotate event metadata")
	}
}
