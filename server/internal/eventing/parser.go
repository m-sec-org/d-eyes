package eventing

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/m-sec-org/d-eyes/server/internal/config"
	"github.com/m-sec-org/d-eyes/server/internal/metrics"
	"github.com/m-sec-org/d-eyes/server/internal/model"
)

// Parser normalizes incoming events before persistence.
type Parser interface {
	Name() string
	Matches(rec *model.SystemEventRecord) bool
	Normalize(rec *model.SystemEventRecord) error
}

// ParserRegistry holds configured parser plugins.
type ParserRegistry struct {
	defaultParser Parser
	parsers       []Parser
	metrics       *metrics.Metrics
}

// NewParserRegistry builds a registry from configuration.
func NewParserRegistry(cfg config.EventsConfig, metricsCollector *metrics.Metrics, log *slog.Logger) (*ParserRegistry, error) {
	reg := &ParserRegistry{
		defaultParser: defaultParser{},
		metrics:       metricsCollector,
	}
	reg.observeConfigured(reg.defaultParser.Name())
	for _, parserCfg := range cfg.Parsers {
		if strings.TrimSpace(parserCfg.Name) == "" || !parserCfg.Enabled {
			continue
		}
		parser, err := newSchemaParser(parserCfg)
		if err != nil {
			return nil, fmt.Errorf("parser %s: %w", parserCfg.Name, err)
		}
		reg.parsers = append(reg.parsers, parser)
		reg.observeConfigured(parserCfg.Name)
		if log != nil {
			log.Info("registered events parser", "name", parserCfg.Name, "event_types", parserCfg.EventTypes, "sources", parserCfg.Sources)
		}
	}
	return reg, nil
}

// Normalize applies the first parser that matches the record.
func (r *ParserRegistry) Normalize(rec *model.SystemEventRecord) error {
	parser := r.match(rec)
	if parser == nil {
		parser = r.defaultParser
	}
	if err := parser.Normalize(rec); err != nil {
		r.recordFailure(parser, err)
		return err
	}
	return nil
}

func (r *ParserRegistry) match(rec *model.SystemEventRecord) Parser {
	if r == nil {
		return nil
	}
	for _, parser := range r.parsers {
		if parser.Matches(rec) {
			return parser
		}
	}
	return nil
}

func (r *ParserRegistry) observeConfigured(name string) {
	if r == nil || r.metrics == nil {
		return
	}
	parserName := strings.TrimSpace(name)
	if parserName == "" {
		parserName = "default"
	}
	r.metrics.SystemEventParsersConfigured.WithLabelValues(parserName).Set(1)
}

func (r *ParserRegistry) recordFailure(parser Parser, err error) {
	if r == nil || r.metrics == nil || err == nil {
		return
	}
	parserName := "default"
	if parser != nil && strings.TrimSpace(parser.Name()) != "" {
		parserName = strings.TrimSpace(parser.Name())
	}
	reason := parserFailureReason(err)
	r.metrics.SystemEventParserFailures.WithLabelValues(parserName, reason).Inc()
}

func parserFailureReason(err error) string {
	var reasonErr interface{ Reason() string }
	if errors.As(err, &reasonErr) {
		if reason := strings.TrimSpace(reasonErr.Reason()); reason != "" {
			return reason
		}
	}
	return "unknown"
}

type defaultParser struct{}

func (defaultParser) Name() string { return "default" }

func (defaultParser) Matches(*model.SystemEventRecord) bool { return true }

func (defaultParser) Normalize(rec *model.SystemEventRecord) error {
	if rec.Metadata == nil {
		rec.Metadata = make(map[string]string)
	}
	if rec.Tags == nil {
		rec.Tags = make(map[string]string)
	}
	return nil
}

type schemaParser struct {
	name             string
	eventTypes       map[string]struct{}
	sources          map[string]struct{}
	collectorKinds   map[string]struct{}
	requiredPayload  []string
	requiredMetadata []string
	requiredTags     []string
	strictPayload    bool
}

func newSchemaParser(cfg config.EventParserConfig) (*schemaParser, error) {
	parser := &schemaParser{
		name:             cfg.Name,
		eventTypes:       toStringSet(cfg.EventTypes),
		sources:          toStringSet(cfg.Sources),
		collectorKinds:   toStringSet(cfg.CollectorKinds),
		requiredPayload:  cfg.RequiredPayload,
		requiredMetadata: cfg.RequiredMetadata,
		requiredTags:     cfg.RequiredTags,
		strictPayload:    cfg.StrictPayload,
	}
	return parser, nil
}

func toStringSet(values []string) map[string]struct{} {
	if len(values) == 0 {
		return nil
	}
	set := make(map[string]struct{}, len(values))
	for _, v := range values {
		if trimmed := strings.ToLower(strings.TrimSpace(v)); trimmed != "" {
			set[trimmed] = struct{}{}
		}
	}
	if len(set) == 0 {
		return nil
	}
	return set
}

func (p *schemaParser) Name() string { return p.name }

func (p *schemaParser) Matches(rec *model.SystemEventRecord) bool {
	if rec == nil {
		return false
	}
	if !matchSet(p.eventTypes, rec.EventType) {
		return false
	}
	if !matchSet(p.sources, rec.Source) {
		return false
	}
	if !matchSet(p.collectorKinds, rec.CollectorKind) {
		return false
	}
	return true
}

func matchSet(set map[string]struct{}, value string) bool {
	if len(set) == 0 {
		return true
	}
	key := strings.ToLower(strings.TrimSpace(value))
	_, ok := set[key]
	return ok
}

func (p *schemaParser) Normalize(rec *model.SystemEventRecord) error {
	if rec.Metadata == nil {
		rec.Metadata = make(map[string]string)
	}
	if rec.Tags == nil {
		rec.Tags = make(map[string]string)
	}
	for _, key := range p.requiredMetadata {
		if strings.TrimSpace(rec.Metadata[key]) == "" {
			return parserErrorf("metadata_missing", "metadata %q is required", key)
		}
	}
	for _, key := range p.requiredTags {
		if strings.TrimSpace(rec.Tags[key]) == "" {
			return parserErrorf("tag_missing", "tag %q is required", key)
		}
	}
	if len(p.requiredPayload) == 0 && !p.strictPayload {
		return nil
	}
	if len(rec.Payload) == 0 {
		return parserErrorf("payload_missing", "payload is required")
	}
	var payload map[string]any
	if err := json.Unmarshal(rec.Payload, &payload); err != nil {
		return parserErrorf("payload_invalid", "payload must be valid json object: %w", err)
	}
	for _, field := range p.requiredPayload {
		if _, ok := lookupField(payload, field); !ok {
			return parserErrorf("payload_field_missing", "payload field %q is required", field)
		}
	}
	if p.strictPayload {
		filtered := make(map[string]any, len(p.requiredPayload))
		for _, field := range p.requiredPayload {
			if val, ok := lookupField(payload, field); ok {
				assignField(filtered, field, val)
			}
		}
		normalized, err := json.Marshal(filtered)
		if err != nil {
			return parserErrorf("payload_normalize_failed", "normalize payload: %w", err)
		}
		rec.Payload = normalized
	}
	return nil
}

type parserError struct {
	reason string
	err    error
}

func (e parserError) Error() string {
	if e.err != nil {
		return e.err.Error()
	}
	return e.reason
}

func (e parserError) Unwrap() error {
	return e.err
}

func (e parserError) Reason() string {
	return e.reason
}

func parserErrorf(reason, format string, args ...any) error {
	return parserError{
		reason: reason,
		err:    fmt.Errorf(format, args...),
	}
}

func lookupField(payload map[string]any, path string) (any, bool) {
	if payload == nil {
		return nil, false
	}
	parts := strings.Split(path, ".")
	var current any = payload
	for _, part := range parts {
		m, ok := current.(map[string]any)
		if !ok {
			return nil, false
		}
		value, ok := m[part]
		if !ok {
			return nil, false
		}
		current = value
	}
	return current, true
}

func assignField(target map[string]any, path string, value any) {
	parts := strings.Split(path, ".")
	current := target
	for idx, part := range parts {
		if idx == len(parts)-1 {
			current[part] = value
			return
		}
		next, ok := current[part]
		if !ok {
			child := make(map[string]any)
			current[part] = child
			current = child
			continue
		}
		child, ok := next.(map[string]any)
		if !ok {
			child = make(map[string]any)
			current[part] = child
		}
		current = child
	}
}
