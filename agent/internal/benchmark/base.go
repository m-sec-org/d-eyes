//go:build linux || windows || darwin

package benchmark

import (
	"context"
	"time"

	"github.com/m-sec-org/d-eyes/agent/internal/progress"
)

// CheckStatus 检查状态枚举
type CheckStatus string

const (
	StatusPass  CheckStatus = "PASS"
	StatusFail  CheckStatus = "FAIL"
	StatusWarn  CheckStatus = "WARN"
	StatusError CheckStatus = "ERROR"
)

// SeverityLevel 风险级别枚举
type SeverityLevel string

const (
	SeverityLow      SeverityLevel = "LOW"
	SeverityMedium   SeverityLevel = "MEDIUM"
	SeverityHigh     SeverityLevel = "HIGH"
	SeverityCritical SeverityLevel = "CRITICAL"
)

// CheckResult 检查结果结构
type CheckResult struct {
	// 检查项ID
	ID string `json:"id"`
	// 检查项名称
	Name string `json:"name"`
	// 检查项描述
	Description string `json:"description"`
	// 检查结果：PASS, FAIL, WARN, ERROR
	Status CheckStatus `json:"status"`
	// 实际值
	ActualValue string `json:"actual_value"`
	// 预期值
	ExpectedValue string `json:"expected_value"`
	// 修复建议
	Remediation string `json:"remediation"`
	// 风险级别：LOW, MEDIUM, HIGH, CRITICAL
	Severity SeverityLevel `json:"severity"`
	// 检查时间
	CheckTime time.Time `json:"check_time"`
}

// BenchmarkChecker 检查器接口
type BenchmarkChecker interface {
	// 初始化检查器
	Init(ctx context.Context) error
	// 执行检查
	Check(ctx context.Context) ([]CheckResult, error)
	// 获取检查项名称
	GetName() string
	// 获取支持的平台
	GetSupportedPlatforms() []string
}

// Scanner 扫描器接口，用于协调整个扫描过程
type Scanner interface {
	// 添加检查器
	AddChecker(checker BenchmarkChecker)
	// 执行扫描
	Scan(ctx context.Context, scope string) ([]CheckResult, error)
	// 获取扫描统计信息
	GetStatistics() map[string]interface{}
	// 设置进度管理器
	SetProgress(manager *progress.Manager)
}

// Config 基线检查配置
type Config struct {
	// 检查范围：os, middleware, database, all
	Scope string `json:"scope"`
	// 是否启用详细日志
	Verbose bool `json:"verbose"`
	// 是否输出调试日志
	Debug bool `json:"debug"`
	// 超时时间（秒）
	Timeout int `json:"timeout"`
	// 自定义配置文件路径
	ConfigFile string `json:"config_file"`
}

// ResultSummary 结果摘要
type ResultSummary struct {
	// 总检查项数
	TotalChecks int `json:"total_checks"`
	// 通过项数
	PassedChecks int `json:"passed_checks"`
	// 失败项数
	FailedChecks int `json:"failed_checks"`
	// 警告项数
	WarningChecks int `json:"warning_checks"`
	// 错误项数
	ErrorChecks int `json:"error_checks"`
	// 按风险级别统计
	SeverityCounts map[SeverityLevel]int `json:"severity_counts"`
	// 扫描开始时间
	StartTime time.Time `json:"start_time"`
	// 扫描结束时间
	EndTime time.Time `json:"end_time"`
	// 扫描耗时（秒）
	Duration float64 `json:"duration"`
}
