//go:build windows

package collector

import (
	"testing"
)

type stubETWParser struct {
	name       string
	providers  []string
	eventLabel string
}

func (p *stubETWParser) Name() string { return p.name }

func (p *stubETWParser) SupportedProviders() []string { return p.providers }

func (p *stubETWParser) Configure(ParserConfig) error { return nil }

func (p *stubETWParser) ParseEvent(*eventRecord) (*SystemEvent, error) {
	return &SystemEvent{
		EventType: p.eventLabel,
		Source:    p.name,
	}, nil
}

func TestDefaultParserManagerHonorsConfig(t *testing.T) {
	cfg := ParserConfig{
		Enabled: []string{"alpha"},
	}
	manager := newDefaultParserManager(cfg)
	manager.RegisterParser(&stubETWParser{name: "alpha", providers: []string{"{11111111-1111-1111-1111-111111111111}"}, eventLabel: "alpha.event"})
	manager.RegisterParser(&stubETWParser{name: "beta", providers: []string{"{22222222-2222-2222-2222-222222222222}"}, eventLabel: "beta.event"})
	var record eventRecord

	event, err := manager.ParseEvent("{11111111-1111-1111-1111-111111111111}", &record)
	if err != nil {
		t.Fatalf("unexpected error parsing event: %v", err)
	}
	if event == nil || event.EventType != "alpha.event" {
		t.Fatalf("expected alpha parser to handle event")
	}

	event, err = manager.ParseEvent("{22222222-2222-2222-2222-222222222222}", &record)
	if err != nil {
		t.Fatalf("unexpected error parsing disabled parser event: %v", err)
	}
	if event != nil && event.EventType == "beta.event" {
		t.Fatalf("beta parser should be disabled via config enabled list")
	}

	_ = manager.UpdateConfig(ParserConfig{
		Disabled: []string{"alpha"},
	})
	event, err = manager.ParseEvent("{11111111-1111-1111-1111-111111111111}", &record)
	if err != nil {
		t.Fatalf("unexpected error parsing after disable: %v", err)
	}
	if event != nil && event.EventType == "alpha.event" {
		t.Fatalf("alpha parser should be disabled after update")
	}
}
