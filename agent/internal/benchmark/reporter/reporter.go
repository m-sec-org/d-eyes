//go:build linux || windows || darwin

package reporter

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"sort"
	"strings"
	"time"

	"github.com/m-sec-org/d-eyes/agent/internal/benchmark"
)

// ReporterType 报告类型
type ReporterType string

const (
	ReporterTypeConsole ReporterType = "console"
	ReporterTypeJSON    ReporterType = "json"
	ReporterTypeCSV     ReporterType = "csv"
	ReporterTypeHTML    ReporterType = "html"
)

// Reporter 报告生成器接口
type Reporter interface {
	// Generate 生成报告
	Generate(results []benchmark.CheckResult, stats map[string]interface{}) ([]byte, error)
	// Export 导出报告到文件
	Export(results []benchmark.CheckResult, stats map[string]interface{}, filePath string) error
}

// ReporterFactory 报告生成器工厂
type ReporterFactory struct{}

// NewReporterFactory 创建报告生成器工厂
func NewReporterFactory() *ReporterFactory {
	return &ReporterFactory{}
}

// CreateReporter 创建报告生成器
func (f *ReporterFactory) CreateReporter(reporterType ReporterType) Reporter {
	switch reporterType {
	case ReporterTypeJSON:
		return NewJSONReporter()
	case ReporterTypeCSV:
		return NewCSVReporter()
	case ReporterTypeHTML:
		return NewHTMLReporter()
	default:
		return NewConsoleReporter()
	}
}

// ConsoleReporter 控制台报告生成器
type ConsoleReporter struct{}

// NewConsoleReporter 创建控制台报告生成器
func NewConsoleReporter() *ConsoleReporter {
	return &ConsoleReporter{}
}

// Generate 生成控制台报告
func (r *ConsoleReporter) Generate(results []benchmark.CheckResult, stats map[string]interface{}) ([]byte, error) {
	var output strings.Builder

	// 打印概览
	output.WriteString("\n=== 基线检查报告概览 ===\n\n")
	if summary, ok := stats["summary"]; ok {
		if summaryData, ok := summary.(benchmark.ResultSummary); ok {
			output.WriteString(fmt.Sprintf("检查总数: %d\n", summaryData.TotalChecks))
			output.WriteString(fmt.Sprintf("通过: %d\n", summaryData.PassedChecks))
			output.WriteString(fmt.Sprintf("失败: %d\n", summaryData.FailedChecks))
			output.WriteString(fmt.Sprintf("警告: %d\n", summaryData.WarningChecks))
			output.WriteString(fmt.Sprintf("错误: %d\n", summaryData.ErrorChecks))
			output.WriteString(fmt.Sprintf("扫描时长: %.2f秒\n\n", summaryData.Duration))

			// 打印风险级别统计
			output.WriteString("风险级别统计:\n")
			output.WriteString(fmt.Sprintf("  紧急: %d\n", summaryData.SeverityCounts[benchmark.SeverityCritical]))
			output.WriteString(fmt.Sprintf("  高危: %d\n", summaryData.SeverityCounts[benchmark.SeverityHigh]))
			output.WriteString(fmt.Sprintf("  中危: %d\n", summaryData.SeverityCounts[benchmark.SeverityMedium]))
			output.WriteString(fmt.Sprintf("  低危: %d\n\n", summaryData.SeverityCounts[benchmark.SeverityLow]))
		}
	}

	// 按状态分类结果
	failedResults := make([]benchmark.CheckResult, 0)
	passedResults := make([]benchmark.CheckResult, 0)
	warningResults := make([]benchmark.CheckResult, 0)

	for _, result := range results {
		switch result.Status {
		case benchmark.StatusFail:
			failedResults = append(failedResults, result)
		case benchmark.StatusPass:
			passedResults = append(passedResults, result)
		case benchmark.StatusWarn:
			warningResults = append(warningResults, result)
		}
	}

	// 按风险级别排序失败结果
	sort.Slice(failedResults, func(i, j int) bool {
		return failedResults[i].Severity > failedResults[j].Severity
	})

	// 打印失败项
	if len(failedResults) > 0 {
		output.WriteString("\n=== 检查失败项 ===\n\n")
		for _, result := range failedResults {
			severityStr := getSeverityString(result.Severity)
			output.WriteString(fmt.Sprintf("[ %s ] %s\n", severityStr, result.Name))
			output.WriteString(fmt.Sprintf("  描述: %s\n", result.Description))
			output.WriteString(fmt.Sprintf("  实际值: %s\n", result.ActualValue))
			output.WriteString(fmt.Sprintf("  预期值: %s\n", result.ExpectedValue))
			output.WriteString(fmt.Sprintf("  修复建议: %s\n\n", result.Remediation))
		}
	}

	return []byte(output.String()), nil
}

// Export 导出控制台报告（打印到控制台）
func (r *ConsoleReporter) Export(results []benchmark.CheckResult, stats map[string]interface{}, filePath string) error {
	content, err := r.Generate(results, stats)
	if err != nil {
		return err
	}

	fmt.Println(string(content))
	return nil
}

// JSONReporter JSON报告生成器
type JSONReporter struct{}

// NewJSONReporter 创建JSON报告生成器
func NewJSONReporter() *JSONReporter {
	return &JSONReporter{}
}

// Generate 生成JSON报告
func (r *JSONReporter) Generate(results []benchmark.CheckResult, stats map[string]interface{}) ([]byte, error) {
	report := map[string]interface{}{
		"results": results,
		"stats":   stats,
	}

	return json.MarshalIndent(report, "", "  ")
}

// Export 导出JSON报告到文件
func (r *JSONReporter) Export(results []benchmark.CheckResult, stats map[string]interface{}, filePath string) error {
	content, err := r.Generate(results, stats)
	if err != nil {
		return err
	}

	return ioutil.WriteFile(filePath, content, 0644)
}

// CSVReporter CSV报告生成器
type CSVReporter struct{}

// NewCSVReporter 创建CSV报告生成器
func NewCSVReporter() *CSVReporter {
	return &CSVReporter{}
}

// Generate 生成CSV报告
func (r *CSVReporter) Generate(results []benchmark.CheckResult, stats map[string]interface{}) ([]byte, error) {
	var output strings.Builder

	// CSV头部
	output.WriteString("ID,名称,描述,状态,实际值,预期值,修复建议,风险级别,检查时间\n")

	// CSV内容
	for _, result := range results {
		statusStr := getStatusString(result.Status)
		severityStr := getSeverityString(result.Severity)

		// 转义CSV特殊字符
		description := escapeCSVField(result.Description)
		actualValue := escapeCSVField(result.ActualValue)
		expectedValue := escapeCSVField(result.ExpectedValue)
		remediation := escapeCSVField(result.Remediation)

		output.WriteString(fmt.Sprintf("%s,%s,%s,%s,%s,%s,%s,%s,%s\n",
			result.ID, result.Name, description, statusStr, actualValue,
			expectedValue, remediation, severityStr, result.CheckTime.Format(time.RFC3339)))
	}

	return []byte(output.String()), nil
}

// Export 导出CSV报告到文件
func (r *CSVReporter) Export(results []benchmark.CheckResult, stats map[string]interface{}, filePath string) error {
	content, err := r.Generate(results, stats)
	if err != nil {
		return err
	}

	return ioutil.WriteFile(filePath, content, 0644)
}

// HTMLReporter HTML报告生成器
type HTMLReporter struct{}

// NewHTMLReporter 创建HTML报告生成器
func NewHTMLReporter() *HTMLReporter {
	return &HTMLReporter{}
}

// Generate 生成HTML报告
func (r *HTMLReporter) Generate(results []benchmark.CheckResult, stats map[string]interface{}) ([]byte, error) {
	var output strings.Builder

	// HTML头部
	output.WriteString(`<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>基线检查报告</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1, h2 { color: #333; }
        .summary { background-color: #f5f5f5; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        table { width: 100%; border-collapse: collapse; margin-bottom: 20px; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #4CAF50; color: white; }
        tr:nth-child(even) { background-color: #f2f2f2; }
        .status-pass { background-color: #dff0d8; }
        .status-fail { background-color: #f2dede; }
        .status-warn { background-color: #fcf8e3; }
        .severity-critical { color: #d32f2f; font-weight: bold; }
        .severity-high { color: #f57c00; font-weight: bold; }
        .severity-medium { color: #f9a825; }
        .severity-low { color: #388e3c; }
    </style>
</head>
<body>
    <h1>基线检查报告</h1>`)

	// 概览部分
	output.WriteString(`
    <div class="summary">
        <h2>检查概览</h2>
        <table>`)

	if summary, ok := stats["summary"]; ok {
		if summaryData, ok := summary.(benchmark.ResultSummary); ok {
			output.WriteString(fmt.Sprintf(`
            <tr>
                <td>检查总数</td>
                <td>%d</td>
            </tr>
            <tr>
                <td>通过</td>
                <td class="status-pass">%d</td>
            </tr>
            <tr>
                <td>失败</td>
                <td class="status-fail">%d</td>
            </tr>
            <tr>
                <td>警告</td>
                <td class="status-warn">%d</td>
            </tr>
            <tr>
                <td>错误</td>
                <td>%d</td>
            </tr>
            <tr>
                <td>扫描时长</td>
                <td>%.2f秒</td>
            </tr>
            <tr>
                <td>紧急风险</td>
                <td class="severity-critical">%d</td>
            </tr>
            <tr>
                <td>高危风险</td>
                <td class="severity-high">%d</td>
            </tr>
            <tr>
                <td>中危风险</td>
                <td class="severity-medium">%d</td>
            </tr>
            <tr>
                <td>低危风险</td>
                <td class="severity-low">%d</td>
            </tr>`,
				summaryData.TotalChecks,
				summaryData.PassedChecks,
				summaryData.FailedChecks,
				summaryData.WarningChecks,
				summaryData.ErrorChecks,
				summaryData.Duration,
				summaryData.SeverityCounts[benchmark.SeverityCritical],
				summaryData.SeverityCounts[benchmark.SeverityHigh],
				summaryData.SeverityCounts[benchmark.SeverityMedium],
				summaryData.SeverityCounts[benchmark.SeverityLow],
			))
		}
	}

	output.WriteString(`
        </table>
    </div>`)

	// 详细结果部分
	output.WriteString(`
    <h2>详细检查结果</h2>
    <table>
        <tr>
            <th>ID</th>
            <th>名称</th>
            <th>描述</th>
            <th>状态</th>
            <th>实际值</th>
            <th>预期值</th>
            <th>修复建议</th>
            <th>风险级别</th>
            <th>检查时间</th>
        </tr>`)

	// 按风险级别和状态排序结果
	sort.Slice(results, func(i, j int) bool {
		// 先按风险级别排序
		if results[i].Severity != results[j].Severity {
			return results[i].Severity > results[j].Severity
		}
		// 再按状态排序
		return results[i].Status < results[j].Status
	})

	for _, result := range results {
		statusStr := getStatusString(result.Status)
		statusClass := getStatusClass(result.Status)
		severityStr := getSeverityString(result.Severity)
		severityClass := getSeverityClass(result.Severity)

		output.WriteString(fmt.Sprintf(`
        <tr>
            <td>%s</td>
            <td>%s</td>
            <td>%s</td>
            <td class="%s">%s</td>
            <td>%s</td>
            <td>%s</td>
            <td>%s</td>
            <td class="%s">%s</td>
            <td>%s</td>
        </tr>`,
			result.ID,
			result.Name,
			escapeHTML(result.Description),
			statusClass,
			statusStr,
			escapeHTML(result.ActualValue),
			escapeHTML(result.ExpectedValue),
			escapeHTML(result.Remediation),
			severityClass,
			severityStr,
			result.CheckTime.Format(time.RFC3339),
		))
	}

	output.WriteString(`
    </table>
</body>
</html>`)

	return []byte(output.String()), nil
}

// Export 导出HTML报告到文件
func (r *HTMLReporter) Export(results []benchmark.CheckResult, stats map[string]interface{}, filePath string) error {
	content, err := r.Generate(results, stats)
	if err != nil {
		return err
	}

	return ioutil.WriteFile(filePath, content, 0644)
}

// 辅助函数

// getStatusString 获取状态字符串
func getStatusString(status benchmark.CheckStatus) string {
	switch status {
	case benchmark.StatusPass:
		return "通过"
	case benchmark.StatusFail:
		return "失败"
	case benchmark.StatusWarn:
		return "警告"
	case benchmark.StatusError:
		return "错误"
	default:
		return "未知"
	}
}

// getSeverityString 获取风险级别字符串
func getSeverityString(severity benchmark.SeverityLevel) string {
	switch severity {
	case benchmark.SeverityCritical:
		return "紧急"
	case benchmark.SeverityHigh:
		return "高危"
	case benchmark.SeverityMedium:
		return "中危"
	case benchmark.SeverityLow:
		return "低危"
	default:
		return "未知"
	}
}

// getStatusClass 获取状态CSS类
func getStatusClass(status benchmark.CheckStatus) string {
	switch status {
	case benchmark.StatusPass:
		return "status-pass"
	case benchmark.StatusFail:
		return "status-fail"
	case benchmark.StatusWarn:
		return "status-warn"
	default:
		return ""
	}
}

// getSeverityClass 获取风险级别CSS类
func getSeverityClass(severity benchmark.SeverityLevel) string {
	switch severity {
	case benchmark.SeverityCritical:
		return "severity-critical"
	case benchmark.SeverityHigh:
		return "severity-high"
	case benchmark.SeverityMedium:
		return "severity-medium"
	case benchmark.SeverityLow:
		return "severity-low"
	default:
		return ""
	}
}

// escapeCSVField 转义CSV字段
func escapeCSVField(field string) string {
	// 如果字段包含逗号、引号或换行符，则需要用引号包围并转义内部引号
	if strings.ContainsAny(field, ",\"\n\r") {
		field = strings.ReplaceAll(field, "\"", "\"\"")
		return fmt.Sprintf("\"%s\"", field)
	}
	return field
}

// escapeHTML 转义HTML特殊字符
func escapeHTML(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, "\"", "&quot;")
	s = strings.ReplaceAll(s, "'", "&#39;")
	return s
}
