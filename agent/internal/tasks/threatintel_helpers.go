package tasks

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/m-sec-org/d-eyes/agent/pkg/reporting"
	"github.com/m-sec-org/d-eyes/agent/pkg/threatintel"
)

type indicatorMatch struct {
	Kind  threatintel.IndicatorKind
	Value string
}

var (
	ipPattern     = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	hashPattern   = regexp.MustCompile(`\b[a-fA-F0-9]{32,64}\b`)
	domainPattern = regexp.MustCompile(`\b([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b`)
	urlPattern    = regexp.MustCompile(`https?://[^\s'"<>]+`)
)

func extractIndicators(text string) []indicatorMatch {
	values := make([]indicatorMatch, 0)
	seen := make(map[string]struct{})

	record := func(kind threatintel.IndicatorKind, value string) {
		value = strings.TrimSpace(value)
		if value == "" {
			return
		}
		key := fmt.Sprintf("%s:%s", kind, strings.ToLower(value))
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		values = append(values, indicatorMatch{Kind: kind, Value: value})
	}

	for _, match := range urlPattern.FindAllString(text, -1) {
		record(threatintel.IndicatorURL, match)
	}
	for _, match := range ipPattern.FindAllString(text, -1) {
		record(threatintel.IndicatorIP, match)
	}
	for _, match := range hashPattern.FindAllString(text, -1) {
		length := len(match)
		if length == 32 || length == 40 || length == 64 {
			record(threatintel.IndicatorHash, match)
		}
	}
	for _, match := range domainPattern.FindAllString(text, -1) {
		match = strings.Trim(match, ".")
		if strings.Contains(match, ".") && !strings.Contains(match, "@") && !strings.Contains(match, "://") {
			record(threatintel.IndicatorDomain, match)
		}
	}
	return values
}

type tiCollector struct {
	req      TaskRequest
	manager  *threatintel.Manager
	findings []threatintel.Finding
	errors   []string
}

func newTICollector(req TaskRequest) *tiCollector {
	if req.ThreatIntel == nil || req.Manager == nil {
		return nil
	}
	return &tiCollector{
		req:     req,
		manager: req.ThreatIntel,
	}
}

func (c *tiCollector) LookupFile(ctx context.Context, path string, metadata map[string]string) {
	if c == nil {
		return
	}
	results, err := c.manager.LookupFile(ctx, path, metadata)
	if err != nil {
		c.errors = append(c.errors, fmt.Sprintf("file %s: %v", path, err))
		return
	}
	c.findings = append(c.findings, results...)
}

func (c *tiCollector) LookupIndicator(ctx context.Context, kind threatintel.IndicatorKind, value string, metadata map[string]string) {
	if c == nil {
		return
	}
	results, err := c.manager.LookupIndicator(ctx, kind, value, metadata)
	if err != nil {
		c.errors = append(c.errors, fmt.Sprintf("indicator %s (%s): %v", value, kind, err))
		return
	}
	c.findings = append(c.findings, results...)
}

func (c *tiCollector) Flush(command, name, label string) ([]reporting.OutputRecord, []string) {
	if c == nil || (len(c.findings) == 0 && len(c.errors) == 0) {
		return nil, nil
	}
	file, path, err := c.req.Manager.CreateFile(command, name, "json")
	if err != nil {
		c.errors = append(c.errors, fmt.Sprintf("create report failed: %v", err))
		return nil, append([]string{}, c.errors...)
	}
	defer file.Close()

	payload := struct {
		Command   string                `json:"command"`
		Profile   string                `json:"profile"`
		Generated time.Time             `json:"generated_at"`
		Findings  []threatintel.Finding `json:"findings"`
		Errors    []string              `json:"errors,omitempty"`
		Metadata  map[string]string     `json:"metadata,omitempty"`
	}{
		Command:   command,
		Profile:   c.req.Profile,
		Generated: time.Now().UTC(),
		Findings:  c.findings,
		Errors:    c.errors,
	}
	if len(c.req.Metadata) > 0 {
		payload.Metadata = c.req.Metadata
	}

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(payload); err != nil {
		c.errors = append(c.errors, fmt.Sprintf("write report failed: %v", err))
		return nil, append([]string{}, c.errors...)
	}

	output := reporting.OutputRecord{
		Label: label,
		Path:  path,
	}
	notes := make([]string, 0)
	if len(c.errors) > 0 {
		notes = append(notes, fmt.Sprintf("威胁情报查询产生 %d 个告警，详见 %s", len(c.errors), path))
	}
	return []reporting.OutputRecord{output}, notes
}
