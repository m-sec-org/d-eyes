//go:build linux || windows || darwin

package reporter

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/m-sec-org/d-eyes/agent/internal/benchmark"
)

func createTestResults() []benchmark.CheckResult {
	now := time.Now()
	return []benchmark.CheckResult{
		{
			ID:            "test_check_1",
			Name:          "测试检查1",
			Description:   "这是第一个测试检查项的详细描述",
			Status:        benchmark.StatusPass,
			ActualValue:   "actual1",
			ExpectedValue: "expected1",
			Remediation:   "这是第一个测试建议",
			Severity:      benchmark.SeverityHigh,
			CheckTime:     now,
		},
		{
			ID:            "test_check_2",
			Name:          "测试检查2",
			Description:   "这是第二个测试检查项的详细描述",
			Status:        benchmark.StatusFail,
			ActualValue:   "actual2",
			ExpectedValue: "expected2",
			Remediation:   "请按照建议进行修复",
			Severity:      benchmark.SeverityCritical,
			CheckTime:     now,
		},
		{
			ID:            "test_check_3",
			Name:          "测试检查3",
			Description:   "这是第三个测试检查项的详细描述",
			Status:        benchmark.StatusWarn,
			ActualValue:   "actual3",
			ExpectedValue: "expected3",
			Remediation:   "建议进行优化",
			Severity:      benchmark.SeverityMedium,
			CheckTime:     now,
		},
	}
}

func createTestStats() map[string]interface{} {
	severityCounts := map[benchmark.SeverityLevel]int{
		benchmark.SeverityCritical: 1,
		benchmark.SeverityHigh:     1,
		benchmark.SeverityMedium:   1,
		benchmark.SeverityLow:      0,
	}

	summary := benchmark.ResultSummary{
		TotalChecks:    3,
		PassedChecks:   1,
		FailedChecks:   1,
		WarningChecks:  1,
		ErrorChecks:    0,
		SeverityCounts: severityCounts,
		StartTime:      time.Now(),
		EndTime:        time.Now().Add(5 * time.Second),
		Duration:       5.0,
	}

	return map[string]interface{}{
		"summary":        summary,
		"total_checkers": 3,
		"platform":       "linux",
	}
}

func TestReporterFactory(t *testing.T) {
	factory := NewReporterFactory()
	assert.NotNil(t, factory)

	// 测试创建不同类型的报告生成器
	consoleReporter := factory.CreateReporter(ReporterTypeConsole)
	assert.NotNil(t, consoleReporter)
	_, ok := consoleReporter.(*ConsoleReporter)
	assert.True(t, ok)

	jsonReporter := factory.CreateReporter(ReporterTypeJSON)
	assert.NotNil(t, jsonReporter)
	_, ok = jsonReporter.(*JSONReporter)
	assert.True(t, ok)

	csvReporter := factory.CreateReporter(ReporterTypeCSV)
	assert.NotNil(t, csvReporter)
	_, ok = csvReporter.(*CSVReporter)
	assert.True(t, ok)

	htmlReporter := factory.CreateReporter(ReporterTypeHTML)
	assert.NotNil(t, htmlReporter)
	_, ok = htmlReporter.(*HTMLReporter)
	assert.True(t, ok)

	// 测试默认情况
	defaultReporter := factory.CreateReporter("unknown_type")
	assert.NotNil(t, defaultReporter)
	_, ok = defaultReporter.(*ConsoleReporter)
	assert.True(t, ok)
}

func TestConsoleReporter_Generate(t *testing.T) {
	reporter := NewConsoleReporter()
	results := createTestResults()
	stats := createTestStats()

	content, err := reporter.Generate(results, stats)
	assert.NoError(t, err)
	assert.NotEmpty(t, content)

	// 验证报告内容
	contentStr := string(content)
	assert.Contains(t, contentStr, "=== 基线检查报告概览 ===")
	assert.Contains(t, contentStr, "检查总数: 3")
	assert.Contains(t, contentStr, "[ 紧急 ] 测试检查2")
	assert.Contains(t, contentStr, "actual2")
}

func TestJSONReporter_Generate(t *testing.T) {
	reporter := NewJSONReporter()
	results := createTestResults()
	stats := createTestStats()

	content, err := reporter.Generate(results, stats)
	assert.NoError(t, err)
	assert.NotEmpty(t, content)

	// 验证JSON格式是否正确
	var report map[string]interface{}
	err = json.Unmarshal(content, &report)
	assert.NoError(t, err)

	// 验证报告内容
	assert.Contains(t, report, "results")
	assert.Contains(t, report, "stats")

	// 验证results字段
	resultsField, ok := report["results"].([]interface{})
	assert.True(t, ok)
	assert.Equal(t, 3, len(resultsField))

	// 验证stats字段
	statsField, ok := report["stats"].(map[string]interface{})
	assert.True(t, ok)
	assert.Contains(t, statsField, "summary")
}

func TestCSVReporter_Generate(t *testing.T) {
	reporter := NewCSVReporter()
	results := createTestResults()
	stats := createTestStats()

	content, err := reporter.Generate(results, stats)
	assert.NoError(t, err)
	assert.NotEmpty(t, content)

	// 验证CSV格式
	contentStr := string(content)
	lines := strings.Split(contentStr, "\n")
	assert.True(t, len(lines) >= 4) // 1 header line + 3 data lines + empty line at end

	// 验证CSV头部
	headerLine := lines[0]
	expectedHeader := "ID,名称,描述,状态,实际值,预期值,修复建议,风险级别,检查时间"
	assert.Contains(t, headerLine, expectedHeader)

	// 验证CSV内容包含所有检查结果
	for _, result := range results {
		assert.Contains(t, contentStr, result.ID)
		assert.Contains(t, contentStr, result.Name)
	}

	// 测试CSV转义功能
	resultsWithSpecialChars := []benchmark.CheckResult{{
		ID:            "test_with_special",
		Name:          "测试，包含逗号",
		Description:   "包含\"引号\"和换行\n的描述",
		Status:        benchmark.StatusPass,
		ActualValue:   "special",
		ExpectedValue: "special",
		Remediation:   "特殊修复建议",
		Severity:      benchmark.SeverityMedium,
		CheckTime:     time.Now(),
	}}

	content, err = reporter.Generate(resultsWithSpecialChars, stats)
	assert.NoError(t, err)
	contentStr = string(content)
	// 验证CSV内容
	assert.Contains(t, contentStr, "test_with_special")
	assert.Contains(t, contentStr, "测试，包含逗号")
	assert.Contains(t, contentStr, "special")
}

func TestHTMLReporter_Generate(t *testing.T) {
	reporter := NewHTMLReporter()
	results := createTestResults()
	stats := createTestStats()

	content, err := reporter.Generate(results, stats)
	assert.NoError(t, err)
	assert.NotEmpty(t, content)

	// 验证HTML格式
	contentStr := string(content)
	assert.Contains(t, contentStr, "<!DOCTYPE html>")
	assert.Contains(t, contentStr, "<html>")
	assert.Contains(t, contentStr, "<body>")
	assert.Contains(t, contentStr, "基线检查报告")

	// 验证概览部分
	assert.Contains(t, contentStr, "<div class=\"summary\">")
	assert.Contains(t, contentStr, "检查总数")
	assert.Contains(t, contentStr, "通过")
	assert.Contains(t, contentStr, "失败")

	// 验证详细结果部分
	assert.Contains(t, contentStr, "<table>")
	assert.Contains(t, contentStr, "<th>ID</th>")
	assert.Contains(t, contentStr, "<th>名称</th>")

	// 验证状态类
	assert.Contains(t, contentStr, "class=\"status-pass\"")
	assert.Contains(t, contentStr, "class=\"status-fail\"")
	assert.Contains(t, contentStr, "class=\"status-warn\"")

	// 验证风险级别类
	assert.Contains(t, contentStr, "class=\"severity-high\"")
	assert.Contains(t, contentStr, "class=\"severity-critical\"")
	assert.Contains(t, contentStr, "class=\"severity-medium\"")

	// 测试HTML转义功能
	resultsWithSpecialChars := []benchmark.CheckResult{{
		ID:            "test_html_special",
		Name:          "HTML <script>测试</script>",
		Description:   "包含&和<>&等特殊字符",
		Status:        benchmark.StatusPass,
		ActualValue:   "html",
		ExpectedValue: "html",
		Remediation:   "HTML修复建议",
		Severity:      benchmark.SeverityMedium,
		CheckTime:     time.Now(),
	}}

	content, err = reporter.Generate(resultsWithSpecialChars, stats)
	assert.NoError(t, err)
	contentStr = string(content)
	// 验证HTML内容包含预期的测试名称和描述
	assert.Contains(t, contentStr, "test_html_special")
	assert.Contains(t, contentStr, "包含&amp;和")
	assert.Contains(t, contentStr, "特殊字符")
}

func TestReporter_Export(t *testing.T) {
	// 创建临时目录
	tempDir, err := os.MkdirTemp("", "reporter-test")
	assert.NoError(t, err)
	defer os.RemoveAll(tempDir)

	results := createTestResults()
	stats := createTestStats()

	// 测试JSON报告导出
	jsonReporter := NewJSONReporter()
	jsonPath := filepath.Join(tempDir, "report.json")
	err = jsonReporter.Export(results, stats, jsonPath)
	assert.NoError(t, err)

	// 验证文件存在
	exists, err := fileExists(jsonPath)
	assert.NoError(t, err)
	assert.True(t, exists)

	// 验证文件内容
	content, err := os.ReadFile(jsonPath)
	assert.NoError(t, err)
	assert.NotEmpty(t, content)

	// 测试CSV报告导出
	csvReporter := NewCSVReporter()
	csvPath := filepath.Join(tempDir, "report.csv")
	err = csvReporter.Export(results, stats, csvPath)
	assert.NoError(t, err)

	// 验证文件存在
	exists, err = fileExists(csvPath)
	assert.NoError(t, err)
	assert.True(t, exists)

	// 测试HTML报告导出
	htmlReporter := NewHTMLReporter()
	htmlPath := filepath.Join(tempDir, "report.html")
	err = htmlReporter.Export(results, stats, htmlPath)
	assert.NoError(t, err)

	// 验证文件存在
	exists, err = fileExists(htmlPath)
	assert.NoError(t, err)
	assert.True(t, exists)

	// 测试控制台报告导出（不生成文件，但不应报错）
	consoleReporter := NewConsoleReporter()
	err = consoleReporter.Export(results, stats, "")
	assert.NoError(t, err)
}

// fileExists 检查文件是否存在
func fileExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}
