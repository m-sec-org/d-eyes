//go:build yara_native

package nativeengine

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	yara "github.com/hillu/go-yara/v4"

	"github.com/m-sec-org/d-eyes/agent/internal/detect/engine"
	"github.com/m-sec-org/d-eyes/agent/internal/detect/engine/goengine"
	"github.com/m-sec-org/d-eyes/agent/internal/detect/scoring"
)

// Bundle implements engine.RuleBundle using libyara.
//
// NOTE: This bundle is only available when built with `-tags yara_native`.
type Bundle struct {
	name      string
	version   string
	rules     *yara.Rules
	ruleCount int
}

// CompileFromSources compiles a libyara ruleset from the provided sources.
// It is intentionally tolerant: individual rule files that fail to compile are skipped
// and recorded in stats, matching the portable engine behaviour.
func CompileFromSources(files map[string][]byte, version string) (*Bundle, goengine.BuildStats, error) {
	stats := goengine.BuildStats{}
	if len(files) == 0 {
		return &Bundle{
			name:      "libyara",
			version:   version,
			rules:     nil,
			ruleCount: 0,
		}, stats, nil
	}

	newCompiler := func() (*yara.Compiler, error) {
		compiler, err := yara.NewCompiler()
		if err != nil {
			return nil, err
		}
		compiler.DisableIncludes()
		return compiler, nil
	}

	compiler, err := newCompiler()
	if err != nil {
		return nil, stats, fmt.Errorf("yara native: init compiler: %w", err)
	}
	destroyCompiler := func() {
		if compiler == nil {
			return
		}
		compiler.Destroy()
		compiler = nil
	}
	defer destroyCompiler()

	keys := make([]string, 0, len(files))
	for k := range files {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	accepted := make([]string, 0, len(keys))
	for _, path := range keys {
		if !strings.HasSuffix(strings.ToLower(path), ".yar") {
			continue
		}
		stats.TotalRuleFiles++
		raw := files[path]
		if len(raw) == 0 {
			recordSkip(&stats, "empty-file")
			continue
		}
		if err := compiler.AddString(string(raw), ""); err != nil {
			recordSkip(&stats, classifyCompileError(err))
			destroyCompiler()
			compiler, err = newCompiler()
			if err != nil {
				return nil, stats, fmt.Errorf("yara native: init compiler: %w", err)
			}
			for _, prev := range accepted {
				if addErr := compiler.AddString(string(files[prev]), ""); addErr != nil {
					destroyCompiler()
					return nil, stats, fmt.Errorf("yara native: rebuild compiler after error: %w", addErr)
				}
			}
			continue
		}
		accepted = append(accepted, path)
		stats.LoadedRuleFiles++
	}

	if len(accepted) == 0 {
		return &Bundle{
			name:      "libyara",
			version:   version,
			rules:     nil,
			ruleCount: 0,
		}, stats, nil
	}

	ruleSet, err := compiler.GetRules()
	if err != nil {
		return nil, stats, fmt.Errorf("yara native: compile rules: %w", err)
	}
	rules := ruleSet.GetRules()
	stats.LoadedRules = len(rules)
	for _, r := range rules {
		hints := parseScoreHints(metaSliceToMap(r.Metas()))
		if hints != (scoring.ScoreHints{}) {
			stats.ScoreHintsSeen++
		}
	}

	return &Bundle{
		name:      "libyara",
		version:   version,
		rules:     ruleSet,
		ruleCount: len(rules),
	}, stats, nil
}

func recordSkip(stats *goengine.BuildStats, reason string) {
	if stats == nil {
		return
	}
	stats.SkippedRuleFiles++
	if stats.SkipReasons == nil {
		stats.SkipReasons = make(map[string]int)
	}
	reason = strings.TrimSpace(reason)
	if reason == "" {
		reason = "unknown"
	}
	stats.SkipReasons[reason]++
}

func classifyCompileError(err error) string {
	if err == nil {
		return "unknown"
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "syntax"):
		return "syntax-error"
	case strings.Contains(msg, "duplicate") || strings.Contains(msg, "already defined"):
		return "duplicate-definition"
	case strings.Contains(msg, "include"):
		return "include-error"
	default:
		return "compile-error"
	}
}

func metaSliceToMap(metas []yara.Meta) map[string]string {
	if len(metas) == 0 {
		return nil
	}
	out := make(map[string]string, len(metas))
	for _, meta := range metas {
		key := strings.TrimSpace(meta.Identifier)
		if key == "" {
			continue
		}
		out[key] = fmt.Sprint(meta.Value)
	}
	return out
}

func parseScoreHints(meta map[string]string) scoring.ScoreHints {
	hints := scoring.ScoreHints{}
	if v, ok := meta["severity"]; ok {
		hints.Severity = strings.ToLower(strings.TrimSpace(v))
	}
	if v, ok := meta["threat"]; ok {
		hints.Threat = strings.ToLower(strings.TrimSpace(v))
	}
	if v, ok := meta["category"]; ok {
		hints.Category = strings.ToLower(strings.TrimSpace(v))
	}
	if v, ok := meta["confidence"]; ok {
		value, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
		if err == nil {
			hints.Confidence = value
		}
	}
	return hints
}

// Name implements engine.RuleBundle.
func (b *Bundle) Name() string {
	if b == nil || strings.TrimSpace(b.name) == "" {
		return "libyara"
	}
	return b.name
}

// Version implements engine.RuleBundle.
func (b *Bundle) Version() string {
	if b == nil || strings.TrimSpace(b.version) == "" {
		return time.Now().UTC().Format(time.RFC3339)
	}
	return b.version
}

// RuleCount implements engine.RuleBundle.
func (b *Bundle) RuleCount() int {
	if b == nil {
		return 0
	}
	return b.ruleCount
}

// Scan implements engine.RuleBundle.
func (b *Bundle) Scan(data []byte, opt engine.ScanOptions) ([]engine.Match, error) {
	if b == nil || b.rules == nil || b.ruleCount == 0 {
		return nil, nil
	}
	var matchRules yara.MatchRules
	if err := b.rules.ScanMem(data, 0, 0, &matchRules); err != nil {
		return nil, fmt.Errorf("yara native: scan memory: %w", err)
	}
	if len(matchRules) == 0 {
		return nil, nil
	}
	out := make([]engine.Match, 0, len(matchRules))
	for _, hit := range matchRules {
		metadata := metaSliceToMap(hit.Metas)
		description := ""
		if v := strings.TrimSpace(metadata["description"]); v != "" {
			description = v
		}
		if strings.TrimSpace(hit.Namespace) != "" {
			if metadata == nil {
				metadata = make(map[string]string, 1)
			}
			metadata["namespace"] = hit.Namespace
		}

		out = append(out, engine.Match{
			RuleName:       hit.Rule,
			Description:    description,
			Tags:           append([]string{}, hit.Tags...),
			FilePath:       opt.FilePath,
			Strings:        groupMatchedStrings(hit.Strings),
			Metadata:       metadata,
			ScoreHints:     parseScoreHints(metadata),
			Partial:        false,
			PartialReasons: nil,
		})
	}
	return out, nil
}

func groupMatchedStrings(stringsHit []yara.MatchString) []engine.MatchedString {
	if len(stringsHit) == 0 {
		return nil
	}
	order := make([]string, 0)
	offsetsByID := make(map[string][]int)
	for _, s := range stringsHit {
		id := s.Name
		if id == "" {
			continue
		}
		if _, ok := offsetsByID[id]; !ok {
			order = append(order, id)
		}
		offsetsByID[id] = append(offsetsByID[id], int(s.Offset))
	}
	out := make([]engine.MatchedString, 0, len(order))
	for _, id := range order {
		offsets := offsetsByID[id]
		sort.Ints(offsets)
		out = append(out, engine.MatchedString{
			Identifier: id,
			Offsets:    offsets,
		})
	}
	return out
}

// Close releases the underlying libyara ruleset.
func (b *Bundle) Close() error {
	if b == nil || b.rules == nil {
		return nil
	}
	b.rules.Destroy()
	b.rules = nil
	b.ruleCount = 0
	return nil
}
