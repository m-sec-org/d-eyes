//go:build windows

package collector

import (
	"strings"
	"sync"
)

type defaultParserManager struct {
	mu            sync.RWMutex
	parsers       map[string]ETWEventParser
	providers     map[string]ETWEventParser
	defaultParser ETWEventParser
	config        ParserConfig
}

func newDefaultParserManager(cfg ParserConfig) *defaultParserManager {
	manager := &defaultParserManager{
		parsers:   make(map[string]ETWEventParser),
		providers: make(map[string]ETWEventParser),
		config:    cfg,
	}
	return manager
}

func (m *defaultParserManager) RegisterParser(parser ETWEventParser) {
	if parser == nil {
		return
	}
	name := normalizeParserName(parser.Name())
	if name == "" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.parsers[name] = parser
	_ = parser.Configure(m.config)
	m.rebuildLocked()
}

func (m *defaultParserManager) ParseEvent(providerGUID string, record *eventRecord) (*SystemEvent, error) {
	m.mu.RLock()
	parser := m.defaultParser
	if providerGUID != "" {
		if p, ok := m.providers[normalizeProviderKey(providerGUID)]; ok {
			parser = p
		}
	}
	m.mu.RUnlock()
	if parser == nil {
		return nil, nil
	}
	return parser.ParseEvent(record)
}

func (m *defaultParserManager) UpdateConfig(cfg ParserConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.config = cfg
	for _, parser := range m.parsers {
		_ = parser.Configure(cfg)
	}
	m.rebuildLocked()
	return nil
}

func (m *defaultParserManager) rebuildLocked() {
	m.providers = make(map[string]ETWEventParser)
	m.defaultParser = nil
	disabled := make(map[string]struct{})
	for _, name := range m.config.Disabled {
		if normalized := normalizeParserName(name); normalized != "" {
			disabled[normalized] = struct{}{}
		}
	}
	enabled := make(map[string]struct{})
	for _, name := range m.config.Enabled {
		if normalized := normalizeParserName(name); normalized != "" {
			enabled[normalized] = struct{}{}
		}
	}
	for name, parser := range m.parsers {
		if _, blocked := disabled[name]; blocked {
			continue
		}
		if len(enabled) > 0 {
			if _, allowed := enabled[name]; !allowed {
				continue
			}
		}
		providers := parser.SupportedProviders()
		if len(providers) == 0 {
			if m.defaultParser == nil {
				m.defaultParser = parser
			}
			continue
		}
		for _, provider := range providers {
			if key := normalizeProviderKey(provider); key != "" {
				m.providers[key] = parser
			}
		}
	}
	if m.defaultParser == nil {
		if parser, ok := m.parsers["default"]; ok {
			m.defaultParser = parser
		}
	}
}

func normalizeParserName(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}

func normalizeProviderKey(provider string) string {
	value := strings.ToLower(strings.TrimSpace(provider))
	if value == "" {
		return ""
	}
	value = strings.Trim(value, "{}")
	return value
}

type defaultETWParser struct{}

func (defaultETWParser) Name() string { return "default" }

func (defaultETWParser) SupportedProviders() []string { return nil }

func (defaultETWParser) ParseEvent(record *eventRecord) (*SystemEvent, error) {
	return convertEventRecord(record), nil
}

func (defaultETWParser) Configure(ParserConfig) error { return nil }
