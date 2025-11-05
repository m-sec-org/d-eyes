//go:build linux || windows || darwin

package benchmark

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestCheckStatus(t *testing.T) {
	tests := []struct {
		status CheckStatus
		want   string
	}{
		{StatusPass, "PASS"},
		{StatusFail, "FAIL"},
		{StatusWarn, "WARN"},
		{StatusError, "ERROR"},
	}

	for _, tt := range tests {
		t.Run(string(tt.status), func(t *testing.T) {
			assert.Equal(t, tt.want, string(tt.status))
		})
	}
}

func TestSeverityLevel(t *testing.T) {
	tests := []struct {
		severity SeverityLevel
		want     string
	}{
		{SeverityLow, "LOW"},
		{SeverityMedium, "MEDIUM"},
		{SeverityHigh, "HIGH"},
		{SeverityCritical, "CRITICAL"},
	}

	for _, tt := range tests {
		t.Run(string(tt.severity), func(t *testing.T) {
			assert.Equal(t, tt.want, string(tt.severity))
		})
	}
}

func TestCheckResult(t *testing.T) {
	checkTime := time.Now()
	result := CheckResult{
		ID:            "check1",
		Name:          "测试检查",
		Description:   "这是一个测试检查",
		Status:        StatusPass,
		ActualValue:   "actual",
		ExpectedValue: "expected",
		Remediation:   "测试修复建议",
		Severity:      SeverityMedium,
		CheckTime:     checkTime,
	}

	assert.Equal(t, "check1", result.ID)
	assert.Equal(t, "测试检查", result.Name)
	assert.Equal(t, "这是一个测试检查", result.Description)
	assert.Equal(t, StatusPass, result.Status)
	assert.Equal(t, "actual", result.ActualValue)
	assert.Equal(t, "expected", result.ExpectedValue)
	assert.Equal(t, "测试修复建议", result.Remediation)
	assert.Equal(t, SeverityMedium, result.Severity)
	assert.Equal(t, checkTime, result.CheckTime)
}

func TestResultSummary(t *testing.T) {
	startTime := time.Now()
	endTime := startTime.Add(5 * time.Second)

	summary := ResultSummary{
		TotalChecks:    10,
		PassedChecks:   6,
		FailedChecks:   2,
		WarningChecks:  1,
		ErrorChecks:    1,
		SeverityCounts: map[SeverityLevel]int{SeverityLow: 3, SeverityMedium: 4, SeverityHigh: 2, SeverityCritical: 1},
		StartTime:      startTime,
		EndTime:        endTime,
		Duration:       5.0,
	}

	assert.Equal(t, 10, summary.TotalChecks)
	assert.Equal(t, 6, summary.PassedChecks)
	assert.Equal(t, 2, summary.FailedChecks)
	assert.Equal(t, 1, summary.WarningChecks)
	assert.Equal(t, 1, summary.ErrorChecks)
	assert.Equal(t, 3, summary.SeverityCounts[SeverityLow])
	assert.Equal(t, 4, summary.SeverityCounts[SeverityMedium])
	assert.Equal(t, 2, summary.SeverityCounts[SeverityHigh])
	assert.Equal(t, 1, summary.SeverityCounts[SeverityCritical])
	assert.Equal(t, startTime, summary.StartTime)
	assert.Equal(t, endTime, summary.EndTime)
	assert.Equal(t, 5.0, summary.Duration)
}

func TestConfig(t *testing.T) {
	config := Config{
		Scope:      "all",
		Verbose:    true,
		Timeout:    300,
		ConfigFile: "/path/to/config.yaml",
	}

	assert.Equal(t, "all", config.Scope)
	assert.Equal(t, true, config.Verbose)
	assert.Equal(t, 300, config.Timeout)
	assert.Equal(t, "/path/to/config.yaml", config.ConfigFile)
}

// MockChecker 模拟检查器实现

type MockChecker struct {
	name               string
	supportedPlatforms []string
	initError          error
	checkResults       []CheckResult
	checkError         error
}

func (m *MockChecker) GetName() string {
	return m.name
}

func (m *MockChecker) GetSupportedPlatforms() []string {
	return m.supportedPlatforms
}

func (m *MockChecker) Init(ctx context.Context) error {
	return m.initError
}

func (m *MockChecker) Check(ctx context.Context) ([]CheckResult, error) {
	return m.checkResults, m.checkError
}
