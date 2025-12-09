package collector

import (
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type ruleFilterEngine struct {
	mu      sync.RWMutex
	include map[string][]string
	exclude map[string][]string
	rules   []FilterRule

	evaluated uint64
	dropped   uint64
	updatedAt atomic.Int64
}

func newRuleFilterEngine(cfg Filters) *ruleFilterEngine {
	engine := &ruleFilterEngine{}
	_ = engine.UpdateConfig(cfg)
	return engine
}

func (e *ruleFilterEngine) ShouldProcess(event *SystemEvent) bool {
	if event == nil {
		return false
	}
	atomic.AddUint64(&e.evaluated, 1)
	e.mu.RLock()
	include := e.include
	exclude := e.exclude
	rules := e.rules
	e.mu.RUnlock()
	if len(include) > 0 && !matchAll(include, event) {
		atomic.AddUint64(&e.dropped, 1)
		return false
	}
	if len(exclude) > 0 && matchAny(exclude, event) {
		atomic.AddUint64(&e.dropped, 1)
		return false
	}
	for _, rule := range rules {
		if !rule.Enabled || !strings.EqualFold(rule.Action, "drop") {
			continue
		}
		if matchRule(rule, event) {
			atomic.AddUint64(&e.dropped, 1)
			return false
		}
	}
	return true
}

func (e *ruleFilterEngine) UpdateConfig(cfg Filters) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.include = cloneStringSliceMap(cfg.Include)
	e.exclude = cloneStringSliceMap(cfg.Exclude)
	if len(cfg.Rules) > 0 {
		e.rules = make([]FilterRule, len(cfg.Rules))
		copy(e.rules, cfg.Rules)
	} else {
		e.rules = nil
	}
	e.updatedAt.Store(time.Now().Unix())
	return nil
}

func (e *ruleFilterEngine) Stats() FilterEngineStats {
	return FilterEngineStats{
		Evaluated: atomic.LoadUint64(&e.evaluated),
		Dropped:   atomic.LoadUint64(&e.dropped),
		UpdatedAt: e.updatedAt.Load(),
	}
}

func matchAll(criteria map[string][]string, event *SystemEvent) bool {
	for field, values := range criteria {
		if !matchField(field, values, event) {
			return false
		}
	}
	return true
}

func matchAny(criteria map[string][]string, event *SystemEvent) bool {
	for field, values := range criteria {
		if matchField(field, values, event) {
			return true
		}
	}
	return false
}

func matchField(field string, values []string, event *SystemEvent) bool {
	if len(values) == 0 {
		return false
	}
	actual := extractField(field, event)
	for _, v := range values {
		if actual == v {
			return true
		}
	}
	return false
}

func extractField(field string, event *SystemEvent) string {
	switch strings.ToLower(field) {
	case "event_type":
		return event.EventType
	case "source":
		return event.Source
	}
	if strings.HasPrefix(field, "metadata.") {
		key := strings.TrimPrefix(field, "metadata.")
		if event.Metadata != nil {
			return event.Metadata[key]
		}
	}
	if strings.HasPrefix(field, "tags.") {
		key := strings.TrimPrefix(field, "tags.")
		if event.Tags != nil {
			return event.Tags[key]
		}
	}
	return ""
}

func matchRule(rule FilterRule, event *SystemEvent) bool {
	if len(rule.Conditions) == 0 {
		return false
	}
	for _, cond := range rule.Conditions {
		if !matchCondition(cond, event) {
			return false
		}
	}
	if rule.Threshold.Count > 0 && rule.Threshold.Window > 0 {
		// Threshold tracking is not yet implemented; treat as immediate match.
	}
	return true
}

func matchCondition(cond FilterCondition, event *SystemEvent) bool {
	fieldValue := extractField(cond.Field, event)
	switch strings.ToLower(cond.Operator) {
	case "equals", "":
		return fieldValue == cond.Value || contains(cond.Values, fieldValue)
	case "not_equals":
		return fieldValue != cond.Value
	}
	return false
}

func contains(arr []string, target string) bool {
	for _, v := range arr {
		if v == target {
			return true
		}
	}
	return false
}
