//go:build linux || windows || darwin

package checkers

import (
	"context"

	"github.com/m-sec-org/d-eyes/agent/internal/benchmark"
	"github.com/m-sec-org/d-eyes/agent/internal/benchmark/engine"
	"github.com/m-sec-org/d-eyes/agent/internal/benchmark/rules"
)

// WebServerChecker Web服务器基线检查器
type WebServerChecker struct {
	name     string
	platform []string
	results  []benchmark.CheckResult
	config   benchmark.Config
	runner   *engine.Runner
	ruleSet  []engine.Rule
}

// NewWebServerChecker 创建Web服务器基线检查器
func NewWebServerChecker(config benchmark.Config) *WebServerChecker {
	ruleSet, _ := rules.LoadWebRules()
	return &WebServerChecker{
		name:     "WebServerChecker",
		platform: []string{"linux", "windows"},
		results:  make([]benchmark.CheckResult, 0),
		config:   config,
		runner:   engine.NewRunner(),
		ruleSet:  ruleSet,
	}
}

// GetName 获取检查器名称
func (w *WebServerChecker) GetName() string {
	return w.name
}

// GetSupportedPlatforms 获取支持的平台
func (w *WebServerChecker) GetSupportedPlatforms() []string {
	return w.platform
}

// Init 初始化检查器
func (w *WebServerChecker) Init(ctx context.Context) error {
	return nil
}

// Check 执行检查
func (w *WebServerChecker) Check(ctx context.Context) ([]benchmark.CheckResult, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	w.results = make([]benchmark.CheckResult, 0)
	for _, rule := range w.ruleSet {
		eval := w.runner.Run(ctx, rule)
		w.results = append(w.results, convertRuleResult(eval))
	}

	return w.results, nil
}

// SetRunner allows tests to inject a custom runner.
func (w *WebServerChecker) SetRunner(r *engine.Runner) {
	w.runner = r
}
