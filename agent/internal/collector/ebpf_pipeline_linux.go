//go:build linux

package collector

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
	"sync"
)

// EBPFEventParser converts decoded syscall events into SystemEvent objects.
type EBPFEventParser interface {
	Name() string
	SupportedEventTypes() []uint32
	Parse(evt *syscallEvent, sourceName, collectorName string) (*SystemEvent, error)
	Configure(ParserConfig) error
}

// EBPFParserManager dispatches raw samples to registered parsers.
type EBPFParserManager interface {
	RegisterParser(parser EBPFEventParser)
	Parse(sample []byte, sourceName, collectorName string) (*SystemEvent, uint64, error)
	UpdateConfig(cfg ParserConfig) error
}

type defaultEBPFParserManager struct {
	mu            sync.RWMutex
	parsers       map[string]EBPFEventParser
	routing       map[uint32]EBPFEventParser
	defaultParser EBPFEventParser
	config        ParserConfig
}

func newEBPFParserManager(cfg ParserConfig) *defaultEBPFParserManager {
	mgr := &defaultEBPFParserManager{
		parsers: make(map[string]EBPFEventParser),
		routing: make(map[uint32]EBPFEventParser),
		config:  cfg,
	}
	return mgr
}

func (m *defaultEBPFParserManager) RegisterParser(parser EBPFEventParser) {
	if parser == nil {
		return
	}
	name := strings.ToLower(strings.TrimSpace(parser.Name()))
	if name == "" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.parsers[name] = parser
	if len(parser.SupportedEventTypes()) == 0 && m.defaultParser == nil {
		m.defaultParser = parser
	}
	m.rebuildRoutingLocked()
}

func (m *defaultEBPFParserManager) UpdateConfig(cfg ParserConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.config = cfg
	for _, parser := range m.parsers {
		_ = parser.Configure(cfg)
	}
	m.rebuildRoutingLocked()
	return nil
}

func (m *defaultEBPFParserManager) Parse(sample []byte, sourceName, collectorName string) (*SystemEvent, uint64, error) {
	evt, err := decodeSyscallEvent(sample)
	if err != nil {
		return nil, 0, err
	}
	parser := m.parserForEvent(evt.EventType)
	if parser == nil {
		parser = m.defaultParser
	}
	if parser == nil {
		return nil, evt.Timestamp, nil
	}
	event, err := parser.Parse(evt, sourceName, collectorName)
	return event, evt.Timestamp, err
}

func (m *defaultEBPFParserManager) parserForEvent(eventType uint32) EBPFEventParser {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if p, ok := m.routing[eventType]; ok {
		return p
	}
	return nil
}

func (m *defaultEBPFParserManager) rebuildRoutingLocked() {
	m.routing = make(map[uint32]EBPFEventParser)
	enabled := make(map[string]bool)
	disabled := make(map[string]bool)
	for _, name := range m.config.Disabled {
		disabled[strings.ToLower(strings.TrimSpace(name))] = true
	}
	if len(m.config.Enabled) > 0 {
		for _, name := range m.config.Enabled {
			enabled[strings.ToLower(strings.TrimSpace(name))] = true
		}
	}
	for name, parser := range m.parsers {
		if disabled[name] {
			continue
		}
		if len(enabled) > 0 && !enabled[name] {
			continue
		}
		for _, code := range parser.SupportedEventTypes() {
			m.routing[code] = parser
		}
		if len(parser.SupportedEventTypes()) == 0 && m.defaultParser == nil {
			m.defaultParser = parser
		}
	}
}

func decodeSyscallEvent(sample []byte) (*syscallEvent, error) {
	expectedSize := binary.Size(syscallEvent{})
	if len(sample) < expectedSize {
		return nil, fmt.Errorf("ebpf sample too small: got %d bytes", len(sample))
	}
	var evt syscallEvent
	reader := bytes.NewReader(sample)
	if err := binary.Read(reader, binary.LittleEndian, &evt); err != nil {
		return nil, fmt.Errorf("decode ebpf event: %w", err)
	}
	return &evt, nil
}
