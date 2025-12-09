//go:build windows

package collector

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"

	"github.com/m-sec-org/d-eyes/agent/internal/plugin"
)

type pluginCloser interface {
	Close() error
}

type etwPluginLoader struct {
	mu        sync.Mutex
	closers   []pluginCloser
	lastNames map[string]struct{}
}

func newETWPluginLoader() *etwPluginLoader {
	return &etwPluginLoader{
		lastNames: make(map[string]struct{}),
	}
}

func (l *etwPluginLoader) teardown() {
	for _, closer := range l.closers {
		_ = closer.Close()
	}
	l.closers = nil
}

func (l *etwPluginLoader) Load(configs []ParserPluginConfig) ([]ETWEventParser, []EventProcessor, []string, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.teardown()
	parsers := make([]ETWEventParser, 0)
	processors := make([]EventProcessor, 0)
	names := make([]string, 0)
	l.lastNames = make(map[string]struct{})
	for _, cfg := range configs {
		if !cfg.Enabled {
			continue
		}
		if strings.TrimSpace(cfg.Name) == "" {
			continue
		}
		if err := l.validateManifest(cfg); err != nil {
			return nil, nil, nil, err
		}
		typ := strings.ToLower(strings.TrimSpace(cfg.Type))
		switch typ {
		case "processor":
			processor, closer, err := l.buildProcessor(cfg)
			if err != nil {
				return nil, nil, nil, err
			}
			if closer != nil {
				l.closers = append(l.closers, closer)
			}
			processors = append(processors, processor)
		default:
			parser, closer, err := l.buildParser(cfg)
			if err != nil {
				return nil, nil, nil, err
			}
			if closer != nil {
				l.closers = append(l.closers, closer)
			}
			parsers = append(parsers, parser)
		}
		names = append(names, cfg.Name)
		l.lastNames[cfg.Name] = struct{}{}
	}
	return parsers, processors, names, nil
}

func (l *etwPluginLoader) validateManifest(cfg ParserPluginConfig) error {
	path := strings.TrimSpace(cfg.Path)
	if path == "" {
		return nil
	}
	if _, err := plugin.LoadManifestFromPath(path); err != nil {
		return fmt.Errorf("plugin %s manifest invalid: %w", cfg.Name, err)
	}
	return nil
}

func (l *etwPluginLoader) buildParser(cfg ParserPluginConfig) (ETWEventParser, pluginCloser, error) {
	switch strings.ToLower(cfg.Type) {
	case "builtin", "", "parser":
		return newCustomProviderParser(cfg)
	default:
		return newCustomProviderParser(cfg)
	}
}

func (l *etwPluginLoader) buildProcessor(cfg ParserPluginConfig) (EventProcessor, pluginCloser, error) {
	switch strings.ToLower(cfg.Type) {
	case "processor":
		return newSuspiciousCommandProcessor(cfg)
	default:
		return newSuspiciousCommandProcessor(cfg)
	}
}

type customProviderParser struct {
	name     string
	provider string
	prefix   string
	metadata map[string]string
}

func newCustomProviderParser(cfg ParserPluginConfig) (ETWEventParser, pluginCloser, error) {
	provider := strings.TrimSpace(cfg.Metadata["provider"])
	if provider == "" {
		provider = strings.TrimSpace(cfg.Metadata["provider_guid"])
	}
	if provider == "" && len(cfg.Config) > 0 {
		if value, ok := cfg.Config["provider"]; ok {
			if parsed, ok := value.(string); ok {
				provider = parsed
			}
		}
	}
	provider = normalizeProviderKey(provider)
	if provider == "" {
		return nil, nil, fmt.Errorf("plugin %s missing provider guid", cfg.Name)
	}
	prefix := cfg.Metadata["event_prefix"]
	if prefix == "" {
		prefix = fmt.Sprintf("windows.plugin.%s", strings.ToLower(cfg.Name))
	}
	return &customProviderParser{
		name:     cfg.Name,
		provider: provider,
		prefix:   prefix,
		metadata: cloneStringMap(cfg.Metadata),
	}, nil, nil
}

func (p *customProviderParser) Name() string { return normalizeParserName(p.name) }

func (p *customProviderParser) SupportedProviders() []string { return []string{p.provider} }

func (p *customProviderParser) ParseEvent(record *eventRecord) (*SystemEvent, error) {
	event := convertEventRecord(record)
	if event == nil {
		return nil, nil
	}
	event.Source = fmt.Sprintf("%s.provider", p.prefix)
	event.EventType = fmt.Sprintf("%s.%d", p.prefix, record.EventHeader.EventDescriptor.Id)
	if event.Metadata == nil {
		event.Metadata = make(map[string]string)
	}
	for k, v := range p.metadata {
		k = strings.ToLower(k)
		if k == "provider" || k == "provider_guid" || k == "event_prefix" {
			continue
		}
		event.Metadata[k] = v
	}
	return event, nil
}

func (p *customProviderParser) Configure(ParserConfig) error { return nil }

type suspiciousCommandProcessor struct {
	name     string
	patterns []string
}

func newSuspiciousCommandProcessor(cfg ParserPluginConfig) (EventProcessor, pluginCloser, error) {
	patterns := []string{"powershell", "invoke-mimikatz", "certutil"}
	if raw, ok := cfg.Config["patterns"]; ok {
		switch val := raw.(type) {
		case []string:
			if len(val) > 0 {
				patterns = val
			}
		case []any:
			tmp := make([]string, 0, len(val))
			for _, item := range val {
				if str, ok := item.(string); ok {
					tmp = append(tmp, str)
				}
			}
			if len(tmp) > 0 {
				patterns = tmp
			}
		}
	}
	return &suspiciousCommandProcessor{
		name:     cfg.Name,
		patterns: patterns,
	}, nil, nil
}

func (p *suspiciousCommandProcessor) Name() string {
	if p == nil || p.name == "" {
		return "processor.suspicious_command"
	}
	return p.name
}

func (p *suspiciousCommandProcessor) Process(_ context.Context, event *SystemEvent) (bool, error) {
	if event == nil || len(p.patterns) == 0 {
		return true, nil
	}
	payloadHex, _ := event.Payload["user_data_hex"].(string)
	payloadHex = strings.ToLower(payloadHex)
	payloadASCII := decodeHexToASCII(payloadHex)
	for _, pattern := range p.patterns {
		pattern = strings.ToLower(pattern)
		if strings.Contains(payloadASCII, pattern) {
			if event.Metadata == nil {
				event.Metadata = make(map[string]string)
			}
			event.Metadata["suspicious.command"] = pattern
			if event.Tags == nil {
				event.Tags = make(map[string]string)
			}
			event.Tags["suspicious"] = "true"
			break
		}
	}
	return true, nil
}

func (p *suspiciousCommandProcessor) Close() error { return nil }

func decodeHexToASCII(hexString string) string {
	if hexString == "" {
		return ""
	}
	data, err := hex.DecodeString(hexString)
	if err != nil {
		return hexString
	}
	return strings.ToLower(string(data))
}
