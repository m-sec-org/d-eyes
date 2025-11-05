//go:build linux || windows || darwin

package checkers

import (
	"context"

	"github.com/m-sec-org/d-eyes/agent/internal/benchmark"
	"github.com/m-sec-org/d-eyes/agent/internal/benchmark/engine"
	"github.com/m-sec-org/d-eyes/agent/internal/benchmark/rules"
)

// OSChecker 操作系统基线检查器接口
type OSChecker interface {
	benchmark.BenchmarkChecker
}

// LinuxOSChecker Linux操作系统基线检查器
type LinuxOSChecker struct {
	name     string
	platform []string
	results  []benchmark.CheckResult
	config   benchmark.Config
	runner   *engine.Runner
	rules    []engine.Rule
}

// WindowsOSChecker Windows操作系统基线检查器
type WindowsOSChecker struct {
	name     string
	platform []string
	results  []benchmark.CheckResult
	config   benchmark.Config
	runner   *engine.Runner
	rules    []engine.Rule
}

// NewLinuxOSChecker 创建Linux操作系统基线检查器
func NewLinuxOSChecker(config benchmark.Config) *LinuxOSChecker {
	ruleSet, _ := rules.LoadOSRules("linux")
	return &LinuxOSChecker{
		name:     "LinuxOSChecker",
		platform: []string{"linux"},
		results:  make([]benchmark.CheckResult, 0),
		config:   config,
		runner:   engine.NewRunner(),
		rules:    ruleSet,
	}
}

// NewWindowsOSChecker 创建Windows操作系统基线检查器
func NewWindowsOSChecker(config benchmark.Config) *WindowsOSChecker {
	ruleSet, _ := rules.LoadOSRules("windows")
	return &WindowsOSChecker{
		name:     "WindowsOSChecker",
		platform: []string{"windows"},
		results:  make([]benchmark.CheckResult, 0),
		config:   config,
		runner:   engine.NewRunner(),
		rules:    ruleSet,
	}
}

// GetName 获取检查器名称
func (c *LinuxOSChecker) GetName() string {
	return c.name
}

// GetName 获取检查器名称
func (w *WindowsOSChecker) GetName() string {
	return w.name
}

// GetSupportedPlatforms 获取支持的平台
func (c *LinuxOSChecker) GetSupportedPlatforms() []string {
	return c.platform
}

// GetSupportedPlatforms 获取支持的平台
func (w *WindowsOSChecker) GetSupportedPlatforms() []string {
	return w.platform
}

// Init 初始化检查器
func (c *LinuxOSChecker) Init(ctx context.Context) error {
	// 初始化Linux特定的检查环境
	return nil
}

// Init 初始化检查器
func (w *WindowsOSChecker) Init(ctx context.Context) error {
	// 初始化Windows特定的检查环境
	return nil
}

// Check 执行检查
func (c *LinuxOSChecker) Check(ctx context.Context) ([]benchmark.CheckResult, error) {
	// 检查上下文是否已取消
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	c.results = make([]benchmark.CheckResult, 0)
	for _, rule := range c.rules {
		eval := c.runner.Run(ctx, rule)
		c.results = append(c.results, convertRuleResult(eval))
	}

	return c.results, nil
}

// Check 执行检查
func (w *WindowsOSChecker) Check(ctx context.Context) ([]benchmark.CheckResult, error) {
	// 检查上下文是否已取消
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	w.results = make([]benchmark.CheckResult, 0)
	for _, rule := range w.rules {
		eval := w.runner.Run(ctx, rule)
		w.results = append(w.results, convertRuleResult(eval))
	}

	return w.results, nil
}

// SetRunner allows tests to inject a custom runner.
func (c *LinuxOSChecker) SetRunner(r *engine.Runner) {
	c.runner = r
}

// SetRunner allows tests to inject a custom runner.
func (w *WindowsOSChecker) SetRunner(r *engine.Runner) {
	w.runner = r
}
