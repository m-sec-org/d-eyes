//go:build linux || windows || darwin

package benchmark

import (
	"context"
	"errors"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestNewScanner(t *testing.T) {
	config := Config{
		Timeout: 300,
	}

	scanner := NewScanner(config)
	assert.NotNil(t, scanner)

	// 验证类型
	scannerImpl, ok := scanner.(*benchmarkScanner)
	assert.True(t, ok)
	assert.Equal(t, 0, len(scannerImpl.checkers))
	assert.Equal(t, config, scannerImpl.config)
}

func TestScanner_AddChecker(t *testing.T) {
	scanner := NewScanner(Config{})

	// 添加支持当前平台的检查器
	currentPlatform := runtime.GOOS
	supportedChecker := &MockChecker{
		name:               "SupportedChecker",
		supportedPlatforms: []string{currentPlatform},
	}
	scanner.AddChecker(supportedChecker)

	// 验证检查器已添加
	scannerImpl, _ := scanner.(*benchmarkScanner)
	assert.Equal(t, 1, len(scannerImpl.checkers))
	assert.Equal(t, "SupportedChecker", scannerImpl.checkers[0].GetName())

	// 添加不支持当前平台的检查器
	unsupportedChecker := &MockChecker{
		name:               "UnsupportedChecker",
		supportedPlatforms: []string{"unsupported_os"},
	}
	scanner.AddChecker(unsupportedChecker)

	// 验证不支持的检查器未添加
	assert.Equal(t, 1, len(scannerImpl.checkers))

	// 添加支持所有平台的检查器
	allPlatformChecker := &MockChecker{
		name:               "AllPlatformChecker",
		supportedPlatforms: []string{"all"},
	}
	scanner.AddChecker(allPlatformChecker)

	// 验证支持所有平台的检查器已添加
	assert.Equal(t, 2, len(scannerImpl.checkers))
	assert.Equal(t, "AllPlatformChecker", scannerImpl.checkers[1].GetName())
}

func TestScanner_Scan(t *testing.T) {
	// 创建测试结果
	checkResults := []CheckResult{
		{
			ID:            "test_check_1",
			Name:          "测试检查1",
			Status:        StatusPass,
			Severity:      SeverityHigh,
			ActualValue:   "",
			ExpectedValue: "",
			Remediation:   "",
			CheckTime:     time.Time{},
		},
		{
			ID:            "test_check_2",
			Name:          "测试检查2",
			Status:        StatusFail,
			Severity:      SeverityMedium,
			ActualValue:   "",
			ExpectedValue: "",
			Remediation:   "",
			CheckTime:     time.Time{},
		},
	}

	// 创建模拟检查器
	checker := &MockChecker{
		name:               "TestChecker",
		supportedPlatforms: []string{runtime.GOOS},
		checkResults:       checkResults,
	}

	// 创建扫描器
	scanner := NewScanner(Config{})
	scanner.AddChecker(checker)

	// 执行扫描
	ctx := context.Background()
	results, err := scanner.Scan(ctx, "all")

	// 验证结果
	assert.NoError(t, err)
	assert.Equal(t, 2, len(results))
	assert.Equal(t, "test_check_1", results[0].ID)
	assert.Equal(t, "test_check_2", results[1].ID)

	// 验证统计信息
	stats := scanner.GetStatistics()
	assert.NotNil(t, stats)
	assert.Contains(t, stats, "summary")
}

func TestScanner_ScanWithError(t *testing.T) {
	// 创建模拟检查器（返回错误）
	checker := &MockChecker{
		name:               "ErrorChecker",
		supportedPlatforms: []string{runtime.GOOS},
		checkError:         errors.New("检查失败"),
		checkResults:       []CheckResult{},
	}

	// 创建扫描器
	scanner := NewScanner(Config{})
	scanner.AddChecker(checker)

	// 执行扫描
	ctx := context.Background()
	results, err := scanner.Scan(ctx, "all")

	// 验证即使有错误也能正常返回（不中断整体扫描）
	assert.NoError(t, err)
	assert.Equal(t, 0, len(results))
}

func TestScanner_ScanWithInitError(t *testing.T) {
	// 创建模拟检查器（初始化错误）
	checker := &MockChecker{
		name:               "InitErrorChecker",
		supportedPlatforms: []string{runtime.GOOS},
		initError:          errors.New("初始化失败"),
		checkResults:       []CheckResult{},
	}

	// 创建扫描器
	scanner := NewScanner(Config{})
	scanner.AddChecker(checker)

	// 执行扫描
	ctx := context.Background()
	results, err := scanner.Scan(ctx, "all")

	// 验证即使初始化错误也能正常返回
	assert.NoError(t, err)
	assert.Equal(t, 0, len(results))
}

// TestScanner_ScanWithContextCancel 测试上下文取消时的扫描行为
func TestScanner_ScanWithContextCancel(t *testing.T) {
	// 创建模拟检查器
	checker := &MockChecker{
		name:               "TestChecker",
		supportedPlatforms: []string{runtime.GOOS},
		checkError:         errors.New("context canceled"), // 模拟检查器返回上下文错误
		checkResults:       []CheckResult{},
	}

	// 创建扫描器
	scanner := NewScanner(Config{})
	scanner.AddChecker(checker)

	// 创建已取消的上下文
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// 执行扫描
	results, err := scanner.Scan(ctx, "all")

	// 验证结果
	assert.NoError(t, err)   // 扫描器应该继续执行，不返回整体错误
	assert.Empty(t, results) // 但应该没有结果返回
}

func TestScanner_ScanWithScope(t *testing.T) {
	// 创建不同类型的检查器
	osChecker := &MockChecker{
		name:               "LinuxOSChecker",
		supportedPlatforms: []string{runtime.GOOS},
		checkResults: []CheckResult{{
			ID:            "os_check",
			Status:        StatusPass,
			ActualValue:   "",
			ExpectedValue: "",
			Remediation:   "",
			CheckTime:     time.Time{},
		}},
	}

	dbChecker := &MockChecker{
		name:               "DatabaseChecker",
		supportedPlatforms: []string{runtime.GOOS},
		checkResults: []CheckResult{{
			ID:            "db_check",
			Status:        StatusPass,
			ActualValue:   "",
			ExpectedValue: "",
			Remediation:   "",
			CheckTime:     time.Time{},
		}},
	}

	// 创建扫描器
	scanner := NewScanner(Config{})
	scanner.AddChecker(osChecker)
	scanner.AddChecker(dbChecker)

	// 测试特定范围扫描
	ctx := context.Background()

	// 扫描OS范围
	osResults, err := scanner.Scan(ctx, "os")
	assert.NoError(t, err)
	assert.Equal(t, 1, len(osResults))
	assert.Equal(t, "os_check", osResults[0].ID)

	// 扫描数据库范围
	dbResults, err := scanner.Scan(ctx, "database")
	assert.NoError(t, err)
	assert.Equal(t, 1, len(dbResults))
	assert.Equal(t, "db_check", dbResults[0].ID)

	// 扫描所有范围
	allResults, err := scanner.Scan(ctx, "all")
	assert.NoError(t, err)
	assert.Equal(t, 2, len(allResults))
}

func TestScanner_GetStatistics(t *testing.T) {
	// 创建扫描器和检查器
	scanner := NewScanner(Config{})
	checker := &MockChecker{
		name:               "StatsChecker",
		supportedPlatforms: []string{runtime.GOOS},
		checkResults: []CheckResult{
			{
				ID:            "check1",
				Status:        StatusPass,
				Severity:      SeverityHigh,
				ActualValue:   "",
				ExpectedValue: "",
				Remediation:   "",
				CheckTime:     time.Time{},
			},
			{
				ID:            "check2",
				Status:        StatusFail,
				Severity:      SeverityCritical,
				ActualValue:   "",
				ExpectedValue: "",
				Remediation:   "",
				CheckTime:     time.Time{},
			},
			{
				ID:            "check3",
				Status:        StatusWarn,
				Severity:      SeverityMedium,
				ActualValue:   "",
				ExpectedValue: "",
				Remediation:   "",
				CheckTime:     time.Time{},
			},
		},
	}
	scanner.AddChecker(checker)

	// 执行扫描
	ctx := context.Background()
	scanner.Scan(ctx, "all")

	// 获取统计信息
	stats := scanner.GetStatistics()
	assert.NotNil(t, stats)

	// 验证统计信息内容
	summary, ok := stats["summary"].(ResultSummary)
	assert.True(t, ok)
	assert.Equal(t, 3, summary.TotalChecks)
	assert.Equal(t, 1, summary.PassedChecks)
	assert.Equal(t, 1, summary.FailedChecks)
	assert.Equal(t, 1, summary.WarningChecks)
	assert.Equal(t, 0, summary.ErrorChecks)

	// 验证风险级别统计
	assert.Equal(t, 1, summary.SeverityCounts[SeverityCritical])
	assert.Equal(t, 1, summary.SeverityCounts[SeverityHigh])
	assert.Equal(t, 1, summary.SeverityCounts[SeverityMedium])
	assert.Equal(t, 0, summary.SeverityCounts[SeverityLow])

	// 验证其他统计信息
	totalCheckers, ok := stats["total_checkers"].(int)
	assert.True(t, ok)
	assert.Equal(t, 1, totalCheckers)

	platform, ok := stats["platform"].(string)
	assert.True(t, ok)
	assert.Equal(t, runtime.GOOS, platform)
}
