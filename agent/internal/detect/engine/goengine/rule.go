package goengine

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/m-sec-org/d-eyes/agent/internal/detect/engine/goengine/metadata"
	"github.com/m-sec-org/d-eyes/agent/internal/detect/scoring"
)

// Rule describes a compiled YARA rule.
type Rule struct {
	Name           string
	Description    string
	Tags           []string
	Metadata       map[string]string
	Strings        []*Pattern
	Condition      Node
	Preconds       []*Precondition
	ScoreHints     scoring.ScoreHints
	Partial        bool
	PartialReasons []string
}

// RuleMatch captures evaluation outcome for a rule.
type RuleMatch struct {
	Strings        []PatternMatch
	Partial        bool
	PartialReasons []string
}

// PatternMatch stores matched string identifier and offsets.
type PatternMatch struct {
	Identifier string
	Offsets    []int
}

// Match evaluates the rule against provided buffers.
func (r *Rule) Match(data []byte, lowerData string, wideData []byte, meta *metadata.FileMetadata) *RuleMatch {
	if len(r.Strings) == 0 {
		return nil
	}

	matchState := make(map[string]PatternMatch, len(r.Strings))
	for _, str := range r.Strings {
		offsets := str.Find(data, lowerData, wideData)
		if len(offsets) == 0 {
			continue
		}
		matchState[str.ID] = PatternMatch{
			Identifier: str.ID,
			Offsets:    offsets,
		}
	}

	ctx := ConditionContext{
		StringIDs:    make([]string, 0, len(r.Strings)),
		Matches:      matchState,
		Placeholders: make(map[string]bool),
	}
	for _, s := range r.Strings {
		ctx.StringIDs = append(ctx.StringIDs, s.ID)
	}

	for _, pc := range r.Preconds {
		ctx.Placeholders[pc.Placeholder] = pc.Eval(data, meta)
	}

	if r.Condition != nil {
		if !r.Condition.Eval(&ctx) {
			return nil
		}
	}

	result := RuleMatch{
		Strings: make([]PatternMatch, 0, len(matchState)),
		Partial: r.Partial,
	}
	if len(r.PartialReasons) > 0 {
		result.PartialReasons = append(result.PartialReasons, r.PartialReasons...)
	}
	for _, m := range matchState {
		result.Strings = append(result.Strings, m)
	}
	return &result
}

// PatternType enumerates supported string pattern forms.
type PatternType int

const (
	patternLiteral PatternType = iota + 1
	patternRegexp
	patternHex
)

// PatternOptions encode modifiers such as wide/nocase.
type PatternOptions struct {
	NoCase   bool
	Wide     bool
	FullWord bool
}

// Pattern stores literal/regex/hex representation.
type Pattern struct {
	ID       string
	Type     PatternType
	Value    string
	Options  PatternOptions
	regex    *regexp.Regexp
	hexBytes []hexToken
}

// hexToken represents single byte condition.
type hexToken interface {
	Match(b byte) bool
}

type exactByte byte

func (e exactByte) Match(b byte) bool { return byte(e) == b }

type anyByte struct{}

func (anyByte) Match(byte) bool { return true }

// Find returns offsets where pattern matched.
func (p *Pattern) Find(data []byte, lower string, wide []byte) []int {
	switch p.Type {
	case patternLiteral:
		return p.findLiteral(data, lower, wide)
	case patternRegexp:
		return p.findRegex(data)
	case patternHex:
		return p.findHex(data)
	default:
		return nil
	}
}

func (p *Pattern) findLiteral(data []byte, lower string, wide []byte) []int {
	if p.Options.Wide {
		return searchWideLiteral(wide, p.Value, p.Options.NoCase, p.Options.FullWord)
	}
	target := p.Value
	if target == "" {
		return nil
	}
	if p.Options.NoCase {
		return searchNoCase(lower, strings.ToLower(target), p.Options.FullWord)
	}
	return searchCaseSensitive(data, []byte(target), p.Options.FullWord)
}

func (p *Pattern) findRegex(data []byte) []int {
	if p.regex == nil {
		return nil
	}
	locs := p.regex.FindAllIndex(data, -1)
	if len(locs) == 0 {
		return nil
	}
	offsets := make([]int, 0, len(locs))
	for _, l := range locs {
		offsets = append(offsets, l[0])
	}
	return offsets
}

func (p *Pattern) findHex(data []byte) []int {
	if len(p.hexBytes) == 0 {
		return nil
	}
	offsets := make([]int, 0)
TOKEN_LOOP:
	for i := 0; i <= len(data)-len(p.hexBytes); i++ {
		for j, token := range p.hexBytes {
			if !token.Match(data[i+j]) {
				continue TOKEN_LOOP
			}
		}
		offsets = append(offsets, i)
	}
	return offsets
}

func searchNoCase(lower string, target string, fullWord bool) []int {
	if target == "" {
		return nil
	}
	offsets := make([]int, 0)
	index := 0
	for {
		pos := strings.Index(lower[index:], target)
		if pos == -1 {
			break
		}
		absolute := index + pos
		if !fullWord || isFullWordBoundary(lower, absolute, len(target)) {
			offsets = append(offsets, absolute)
		}
		index = absolute + 1
	}
	return offsets
}

func searchCaseSensitive(data []byte, target []byte, fullWord bool) []int {
	if len(target) == 0 {
		return nil
	}
	offsets := make([]int, 0)
	index := 0
	for {
		pos := bytesIndex(data[index:], target)
		if pos == -1 {
			break
		}
		absolute := index + pos
		if !fullWord || isFullWordBoundaryBytes(data, absolute, len(target)) {
			offsets = append(offsets, absolute)
		}
		index = absolute + 1
	}
	return offsets
}

func searchWideLiteral(wide []byte, val string, nocase bool, fullWord bool) []int {
	if len(wide) == 0 || val == "" {
		return nil
	}
	pattern := make([]byte, 0, len(val)*2)
	for _, r := range val {
		// we only support BMP subset for now
		pattern = append(pattern, byte(r))
		pattern = append(pattern, 0x00)
	}
	offsets := make([]int, 0)
	index := 0
	for {
		pos := bytesIndex(wide[index:], pattern)
		if pos == -1 {
			break
		}
		absolute := index + pos
		// convert offset back to original bytes index
		byteOffset := absolute / 2
		if !fullWord || isFullWordBoundaryBytes(wide, absolute, len(pattern)) {
			offsets = append(offsets, byteOffset)
		}
		index = absolute + 2
	}
	return offsets
}

func bytesIndex(data []byte, pattern []byte) int {
	return bytes.Index(data, pattern)
}

func isAlphaNum(b byte) bool {
	if b >= 'a' && b <= 'z' {
		return true
	}
	if b >= 'A' && b <= 'Z' {
		return true
	}
	if b >= '0' && b <= '9' {
		return true
	}
	if b == '_' {
		return true
	}
	return false
}

func isFullWordBoundaryBytes(data []byte, offset int, length int) bool {
	if offset > 0 {
		if isAlphaNum(data[offset-1]) {
			return false
		}
	}
	after := offset + length
	if after < len(data) {
		if isAlphaNum(data[after]) {
			return false
		}
	}
	return true
}

func isFullWordBoundary(str string, offset int, length int) bool {
	if offset > 0 {
		if isAlphaNum(str[offset-1]) {
			return false
		}
	}
	after := offset + length
	if after < len(str) {
		if isAlphaNum(str[after]) {
			return false
		}
	}
	return true
}

// compilePattern initialises regex/hex helper based on pattern type.
func compilePattern(p *Pattern) error {
	switch p.Type {
	case patternLiteral:
		return nil
	case patternRegexp:
		regexValue := p.Value
		flags := ""
		if strings.HasSuffix(regexValue, "/i") {
			regexValue = strings.TrimSuffix(regexValue, "/i")
			flags = "(?i)"
		}
		if strings.HasPrefix(regexValue, "/") && strings.HasSuffix(regexValue, "/") {
			regexValue = regexValue[1 : len(regexValue)-1]
		}
		compiled, err := regexp.Compile(flags + regexValue)
		if err != nil {
			return fmt.Errorf("regex compile: %w", err)
		}
		p.regex = compiled
	case patternHex:
		tokens, err := parseHexTokens(p.Value)
		if err != nil {
			return err
		}
		p.hexBytes = tokens
	default:
		return fmt.Errorf("unknown pattern type")
	}
	return nil
}

func parseHexTokens(input string) ([]hexToken, error) {
	input = strings.TrimSpace(input)
	if strings.HasPrefix(input, "{") && strings.HasSuffix(input, "}") {
		input = strings.TrimSpace(input[1 : len(input)-1])
	}
	if input == "" {
		return nil, nil
	}
	parts := strings.Fields(input)
	tokens := make([]hexToken, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		switch part {
		case "??":
			tokens = append(tokens, anyByte{})
			continue
		default:
			if strings.Contains(part, "?") {
				return nil, fmt.Errorf("hex nibble wildcard unsupported: %s", part)
			}
			b, err := hex.DecodeString(part)
			if err != nil || len(b) != 1 {
				return nil, fmt.Errorf("invalid hex token %s", part)
			}
			tokens = append(tokens, exactByte(b[0]))
		}
	}
	return tokens, nil
}

// parsePatternOptions extracts modifiers like wide/nocase/fullword.
func parsePatternOptions(parts []string) PatternOptions {
	opts := PatternOptions{}
	for _, part := range parts {
		switch strings.ToLower(part) {
		case "nocase":
			opts.NoCase = true
		case "wide":
			opts.Wide = true
		case "fullword":
			opts.FullWord = true
		}
	}
	return opts
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
		value, err := strconv.ParseFloat(v, 64)
		if err == nil {
			hints.Confidence = value
		}
	}
	return hints
}
