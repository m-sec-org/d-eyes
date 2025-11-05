package goengine

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

var (
	commentInlineRe = regexp.MustCompile(`//.*`)
	commentBlockRe  = regexp.MustCompile(`/\*[\s\S]*?\*/`)
	headerUintRe    = regexp.MustCompile(`uint(8|16|32)(be)?\s*\(\s*(\d+)\s*\)\s*==\s*(0x[0-9a-fA-F]+|\d+)`)
	filesizeRe      = regexp.MustCompile(`filesize\s*(<=|>=|<|>|==)\s*([0-9]+)([kKmMgG][bB])?`)
	metaKeyValueRe  = regexp.MustCompile(`([A-Za-z0-9_]+)\s*=\s*("[^"]*"|[^"\n]+)`)
	stringAssignRe  = regexp.MustCompile(`^\s*(\$[A-Za-z0-9_]+)\s*=\s*(.+)$`)
	tagLineRe       = regexp.MustCompile(`^tags\s*=\s*(.+)$`)
	tokenWhitespace = regexp.MustCompile(`\s+`)
)

type parserState int

type parser struct {
	sourcePath string
	input      string
}

func newParser(path string, content string) *parser {
	return &parser{
		sourcePath: path,
		input:      content,
	}
}

func (p *parser) Parse() ([]*Rule, error) {
	withoutComments := commentBlockRe.ReplaceAllString(p.input, "")
	withoutComments = commentInlineRe.ReplaceAllString(withoutComments, "")

	rules := make([]*Rule, 0)
	cursor := 0
	for cursor < len(withoutComments) {
		index := strings.Index(withoutComments[cursor:], "rule ")
		if index == -1 {
			break
		}
		cursor += index
		name, body, jump, err := p.extractRule(withoutComments[cursor:])
		if err != nil {
			return nil, fmt.Errorf("%s: %w", filepath.Base(p.sourcePath), err)
		}
		cursor += jump

		rule, err := p.parseRule(name, body)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", filepath.Base(p.sourcePath), err)
		}
		if rule != nil {
			rules = append(rules, rule)
		}
	}
	return rules, nil
}

func (p *parser) extractRule(input string) (string, string, int, error) {
	headerEnd := strings.Index(input, "{")
	if headerEnd == -1 {
		return "", "", 0, fmt.Errorf("missing '{' after rule declaration")
	}
	header := strings.TrimSpace(input[:headerEnd])
	parts := strings.Fields(header)
	if len(parts) < 2 {
		return "", "", 0, fmt.Errorf("invalid rule declaration: %s", header)
	}
	name := parts[len(parts)-1]
	bodyStart := headerEnd + 1
	braces := 1
	i := bodyStart
	for i < len(input) && braces > 0 {
		switch input[i] {
		case '{':
			braces++
		case '}':
			braces--
		}
		i++
	}
	if braces != 0 {
		return "", "", 0, fmt.Errorf("unbalanced braces for rule %s", name)
	}
	body := strings.TrimSpace(input[bodyStart : i-1])
	return name, body, i, nil
}

func (p *parser) parseRule(name, body string) (*Rule, error) {
	rule := &Rule{
		Name:     name,
		Metadata: make(map[string]string),
	}

	sections := splitSections(body)
	if metaBody, ok := sections["meta"]; ok {
		meta := p.parseMeta(metaBody)
		for k, v := range meta {
			rule.Metadata[k] = v
		}
		if desc, ok := meta["description"]; ok {
			rule.Description = strings.Trim(desc, `"`)
		}
		if tags, ok := meta["tags"]; ok {
			rule.Tags = parseCSV(tags)
		}
	}

	if strBody, ok := sections["strings"]; ok {
		var err error
		rule.Strings, err = p.parseStrings(strBody)
		if err != nil {
			return nil, fmt.Errorf("%s strings: %w", name, err)
		}
	}

	if condBody, ok := sections["condition"]; ok {
		condBody = strings.TrimSpace(condBody)
		preconds, placeholderCondition := extractPreconditions(condBody)
		rule.Preconds = preconds
		if strings.TrimSpace(placeholderCondition) != "" {
			node, err := compileCondition(placeholderCondition)
			if err != nil {
				return nil, fmt.Errorf("%s condition: %w", name, err)
			}
			rule.Condition = node
		}
	}

	rule.ScoreHints = parseScoreHints(rule.Metadata)
	return rule, nil
}

func splitSections(body string) map[string]string {
	result := make(map[string]string)
	currentSection := ""
	var builder strings.Builder

	lines := strings.Split(body, "\n")
	for _, line := range lines {
		trim := strings.TrimSpace(line)
		switch {
		case trim == "":
			if currentSection == "" {
				continue
			}
		case strings.HasSuffix(trim, ":"):
			if currentSection != "" {
				result[currentSection] = strings.TrimSpace(builder.String())
				builder.Reset()
			}
			currentSection = strings.TrimSuffix(trim, ":")
			continue
		default:
			if builder.Len() > 0 {
				builder.WriteString("\n")
			}
			builder.WriteString(line)
		}
	}
	if currentSection != "" && builder.Len() > 0 {
		result[currentSection] = strings.TrimSpace(builder.String())
	}
	return result
}

func (p *parser) parseMeta(body string) map[string]string {
	meta := make(map[string]string)
	lines := strings.Split(body, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		matches := metaKeyValueRe.FindStringSubmatch(line)
		if len(matches) != 3 {
			continue
		}
		key := strings.TrimSpace(matches[1])
		value := strings.TrimSpace(matches[2])
		meta[key] = value
	}
	return meta
}

func (p *parser) parseStrings(body string) ([]*Pattern, error) {
	lines := strings.Split(body, "\n")
	patterns := make([]*Pattern, 0)
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		matches := stringAssignRe.FindStringSubmatch(line)
		if len(matches) != 3 {
			continue
		}
		id := matches[1]
		payload := strings.TrimSpace(matches[2])
		pattern, err := parsePattern(id, payload)
		if err != nil {
			return nil, err
		}
		if err := compilePattern(pattern); err != nil {
			return nil, err
		}
		patterns = append(patterns, pattern)
	}
	return patterns, nil
}

func parsePattern(id, payload string) (*Pattern, error) {
	parts := tokenWhitespace.Split(strings.TrimSpace(payload), -1)
	if len(parts) == 0 {
		return nil, fmt.Errorf("empty pattern for %s", id)
	}

	value := parts[0]
	modifiers := parts[1:]
	pattern := &Pattern{
		ID:      id,
		Value:   strings.TrimSpace(value),
		Options: parsePatternOptions(modifiers),
	}

	switch {
	case strings.HasPrefix(value, "{"):
		pattern.Type = patternHex
	case strings.HasPrefix(value, "/"):
		pattern.Type = patternRegexp
	case strings.HasPrefix(value, "\""):
		pattern.Type = patternLiteral
		pattern.Value = strings.Trim(pattern.Value, `"`)
	default:
		pattern.Type = patternLiteral
	}

	return pattern, nil
}

// compileCondition builds AST for boolean expression.
func compileCondition(condition string) (Node, error) {
	parser := newConditionParser(condition)
	return parser.parseExpression()
}

// extractPreconditions returns header checks replaced with placeholders.
func extractPreconditions(condition string) ([]*Precondition, string) {
	placeholders := make([]*Precondition, 0)
	result := condition

	result = headerUintRe.ReplaceAllStringFunc(result, func(match string) string {
		sub := headerUintRe.FindStringSubmatch(match)
		if len(sub) != 6 {
			return match
		}
		bits := atoi(sub[1])
		isBig := sub[2] == "be"
		offset := atoi(sub[3])
		valueStr := sub[4]
		value := parseInt(valueStr)
		placeholder := fmt.Sprintf("__pc%d", len(placeholders))
		placeholders = append(placeholders, &Precondition{
			Placeholder: placeholder,
			Eval: func(data []byte) bool {
				switch bits {
				case 8:
					if offset < len(data) {
						return uint64(data[offset]) == value
					}
				case 16:
					if offset+1 < len(data) {
						if isBig {
							return uint64(data[offset])<<8|uint64(data[offset+1]) == value
						}
						return uint64(data[offset+1])<<8|uint64(data[offset]) == value
					}
				case 32:
					if offset+3 < len(data) {
						if isBig {
							return (uint64(data[offset])<<24 | uint64(data[offset+1])<<16 | uint64(data[offset+2])<<8 | uint64(data[offset+3])) == value
						}
						return (uint64(data[offset+3])<<24 | uint64(data[offset+2])<<16 | uint64(data[offset+1])<<8 | uint64(data[offset])) == value
					}
				}
				return false
			},
		})
		return placeholder
	})

	result = filesizeRe.ReplaceAllStringFunc(result, func(match string) string {
		sub := filesizeRe.FindStringSubmatch(match)
		if len(sub) != 4 {
			return match
		}
		comp := sub[1]
		value := atoi(sub[2])
		if sub[3] != "" {
			value = withUnit(value, sub[3])
		}
		placeholder := fmt.Sprintf("__pc%d", len(placeholders))
		placeholders = append(placeholders, &Precondition{
			Placeholder: placeholder,
			Eval: func(data []byte) bool {
				switch comp {
				case "<":
					return len(data) < value
				case "<=":
					return len(data) <= value
				case ">":
					return len(data) > value
				case ">=":
					return len(data) >= value
				case "==":
					return len(data) == value
				}
				return false
			},
		})
		return placeholder
	})

	return placeholders, result
}

func parseInt(str string) uint64 {
	if strings.HasPrefix(str, "0x") || strings.HasPrefix(str, "0X") {
		value, err := strconv.ParseUint(str[2:], 16, 64)
		if err != nil {
			return 0
		}
		return value
	}
	value, err := strconv.ParseUint(str, 10, 64)
	if err != nil {
		return 0
	}
	return value
}

func withUnit(value int, unit string) int {
	unit = strings.ToLower(unit)
	switch unit {
	case "kb":
		return value * 1024
	case "mb":
		return value * 1024 * 1024
	case "gb":
		return value * 1024 * 1024 * 1024
	default:
		return value
	}
}

func parseCSV(raw string) []string {
	items := strings.Split(raw, ",")
	result := make([]string, 0, len(items))
	for _, item := range items {
		item = strings.Trim(strings.TrimSpace(item), `"`)
		if item == "" {
			continue
		}
		result = append(result, item)
	}
	return result
}
