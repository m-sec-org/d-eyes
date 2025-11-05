//go:build linux || windows || darwin

package checkers

import (
	"context"

	"github.com/m-sec-org/d-eyes/agent/internal/benchmark"
	"github.com/m-sec-org/d-eyes/agent/internal/benchmark/engine"
	"github.com/m-sec-org/d-eyes/agent/internal/benchmark/rules"
)

// AppServerChecker 应用服务器基线检查器
type AppServerChecker struct {
	name     string
	platform []string
	results  []benchmark.CheckResult
	config   benchmark.Config
	runner   *engine.Runner
	ruleSet  []engine.Rule
}

// NewAppServerChecker 创建应用服务器基线检查器
func NewAppServerChecker(config benchmark.Config) *AppServerChecker {
	ruleSet, _ := rules.LoadAppServerRules()
	return &AppServerChecker{
		name:     "AppServerChecker",
		platform: []string{"linux", "windows"},
		results:  make([]benchmark.CheckResult, 0),
		config:   config,
		runner:   engine.NewRunner(),
		ruleSet:  ruleSet,
	}
}

// GetName 获取检查器名称
func (a *AppServerChecker) GetName() string {
	return a.name
}

// GetSupportedPlatforms 获取支持的平台
func (a *AppServerChecker) GetSupportedPlatforms() []string {
	return a.platform
}

// Init 初始化检查器
func (a *AppServerChecker) Init(ctx context.Context) error {
	return nil
}

// Check 执行检查
func (a *AppServerChecker) Check(ctx context.Context) ([]benchmark.CheckResult, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	a.results = make([]benchmark.CheckResult, 0)
	for _, rule := range a.ruleSet {
		eval := a.runner.Run(ctx, rule)
		a.results = append(a.results, convertRuleResult(eval))
	}

	return a.results, nil
}

// SetRunner allows tests to inject a custom runner.
func (a *AppServerChecker) SetRunner(r *engine.Runner) {
	a.runner = r
}
