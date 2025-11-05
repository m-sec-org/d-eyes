package goengine

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/m-sec-org/d-eyes/agent/internal/detect/engine"
)

// Engine implements engine.RuleBundle using a pure Go matcher.
type Engine struct {
	name      string
	version   string
	rules     []*Rule
	ruleIndex map[string]*Rule
}

// NewEngine creates a compiled rule bundle.
func NewEngine(name, version string, rules []*Rule) *Engine {
	ruleIndex := make(map[string]*Rule, len(rules))
	for _, r := range rules {
		ruleIndex[r.Name] = r
	}
	return &Engine{
		name:      name,
		version:   version,
		rules:     rules,
		ruleIndex: ruleIndex,
	}
}

// Name returns human readable bundle name.
func (e *Engine) Name() string {
	if e.name != "" {
		return e.name
	}
	return "default"
}

// Version returns semantic version string or timestamp.
func (e *Engine) Version() string {
	if e.version != "" {
		return e.version
	}
	return time.Now().UTC().Format(time.RFC3339)
}

// RuleCount returns number of loaded rules.
func (e *Engine) RuleCount() int {
	return len(e.rules)
}

// Scan evaluates rules against provided payload.
func (e *Engine) Scan(data []byte, opt engine.ScanOptions) ([]engine.Match, error) {
	if len(e.rules) == 0 {
		return nil, nil
	}

	fileLower := strings.ToLower(string(data))
	wideData := buildWideBuffer(data)

	matches := make([]engine.Match, 0)
	for _, rule := range e.rules {
		result := rule.Match(data, fileLower, wideData)
		if result == nil {
			continue
		}

		match := engine.Match{
			RuleName:    rule.Name,
			Description: rule.Description,
			Tags:        append([]string{}, rule.Tags...),
			FilePath:    opt.FilePath,
			Strings:     make([]engine.MatchedString, 0, len(result.Strings)),
			Metadata:    cloneMetadata(rule.Metadata),
			ScoreHints:  rule.ScoreHints,
		}
		for _, hit := range result.Strings {
			match.Strings = append(match.Strings, engine.MatchedString{
				Identifier: hit.Identifier,
				Offsets:    append([]int{}, hit.Offsets...),
			})
		}
		matches = append(matches, match)
	}

	return matches, nil
}

// buildWideBuffer returns a UTF-16LE like view of ASCII bytes for wide pattern quick search.
func buildWideBuffer(data []byte) []byte {
	if len(data) == 0 {
		return nil
	}
	buf := bytes.NewBuffer(make([]byte, 0, len(data)*2))
	for _, b := range data {
		buf.WriteByte(b)
		buf.WriteByte(0x00)
	}
	return buf.Bytes()
}

// RuleFromSource constructs Rule list from raw file content.
func RuleFromSource(path string, content []byte) ([]*Rule, error) {
	parser := newParser(path, string(content))
	return parser.Parse()
}

// FromDirectory compiles all .yar files inside provided map (path->content).
func FromDirectory(files map[string][]byte, version string) (*Engine, error) {
	ruleList := make([]*Rule, 0)
	keys := make([]string, 0, len(files))
	for k := range files {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	skipped := make([]string, 0)
	for _, path := range keys {
		if !strings.HasSuffix(strings.ToLower(path), ".yar") {
			continue
		}
		items, err := RuleFromSource(path, files[path])
		if err != nil {
			if isUnsupportedError(err) {
				skipped = append(skipped, filepath.Base(path))
				continue
			}
			return nil, fmt.Errorf("parse %s: %w", filepath.Base(path), err)
		}
		ruleList = append(ruleList, items...)
	}
	if len(skipped) > 0 {
		log.Printf("yara: skipped %d rule files due to unsupported features: %s", len(skipped), strings.Join(skipped, ", "))
	}
	return NewEngine("embedded", version, ruleList), nil
}

func isUnsupportedError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, engine.ErrUnsupportedFeature) {
		return true
	}
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "unsupported") {
		return true
	}
	if strings.Contains(msg, "invalid hex token") {
		return true
	}
	if strings.Contains(msg, "invalid group element") {
		return true
	}
	return false
}

func cloneMetadata(src map[string]string) map[string]string {
	if len(src) == 0 {
		return nil
	}
	dst := make(map[string]string, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}
