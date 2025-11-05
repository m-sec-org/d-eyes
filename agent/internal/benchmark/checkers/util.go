package checkers

import (
	"strings"
	"time"

	"github.com/m-sec-org/d-eyes/agent/internal/benchmark"
	"github.com/m-sec-org/d-eyes/agent/internal/benchmark/engine"
)

func severityFromString(v string) benchmark.SeverityLevel {
	switch strings.ToUpper(strings.TrimSpace(v)) {
	case "CRITICAL":
		return benchmark.SeverityCritical
	case "HIGH":
		return benchmark.SeverityHigh
	case "MEDIUM":
		return benchmark.SeverityMedium
	case "LOW":
		return benchmark.SeverityLow
	default:
		return benchmark.SeverityLow
	}
}

func convertRuleResult(res engine.RuleResult) benchmark.CheckResult {
	status := benchmark.StatusWarn
	switch res.Status {
	case engine.StatusPass:
		status = benchmark.StatusPass
	case engine.StatusFail:
		status = benchmark.StatusFail
	case engine.StatusError:
		status = benchmark.StatusError
	case engine.StatusWarn:
		status = benchmark.StatusWarn
	}

	actual := ""
	expected := ""
	if len(res.Details) > 0 {
		d := res.Details[0]
		actual = strings.TrimSpace(d.Actual)
		expected = strings.TrimSpace(d.Expected)
		if d.Message != "" && actual == "" {
			actual = d.Message
		}
	}

	return benchmark.CheckResult{
		ID:            res.Rule.ID,
		Name:          res.Rule.Title,
		Description:   res.Rule.Description,
		Status:        status,
		ActualValue:   actual,
		ExpectedValue: expected,
		Remediation:   res.Rule.Remediation,
		Severity:      severityFromString(res.Rule.Severity),
		CheckTime:     time.Now(),
	}
}
