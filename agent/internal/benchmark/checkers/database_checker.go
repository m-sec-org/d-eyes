//go:build linux || windows || darwin

package checkers

import (
	"context"

	"github.com/m-sec-org/d-eyes/agent/internal/benchmark"
	"github.com/m-sec-org/d-eyes/agent/internal/benchmark/engine"
	"github.com/m-sec-org/d-eyes/agent/internal/benchmark/rules"
)

// DatabaseChecker 数据库基线检查器
type DatabaseChecker struct {
	name     string
	platform []string
	results  []benchmark.CheckResult
	config   benchmark.Config
	runner   *engine.Runner
	ruleSet  []engine.Rule
}

// NewDatabaseChecker 创建数据库基线检查器
func NewDatabaseChecker(config benchmark.Config) *DatabaseChecker {
	ruleSet, _ := rules.LoadDatabaseRules()
	return &DatabaseChecker{
		name:     "DatabaseChecker",
		platform: []string{"linux", "windows", "darwin"},
		results:  make([]benchmark.CheckResult, 0),
		config:   config,
		runner:   engine.NewRunner(),
		ruleSet:  ruleSet,
	}
}

// GetName 获取检查器名称
func (d *DatabaseChecker) GetName() string {
	return d.name
}

// GetSupportedPlatforms 获取支持的平台
func (d *DatabaseChecker) GetSupportedPlatforms() []string {
	return d.platform
}

// Init 初始化检查器
func (d *DatabaseChecker) Init(ctx context.Context) error {
	return nil
}

// Check 执行检查
func (d *DatabaseChecker) Check(ctx context.Context) ([]benchmark.CheckResult, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	d.results = make([]benchmark.CheckResult, 0)
	for _, rule := range d.ruleSet {
		eval := d.runner.Run(ctx, rule)
		d.results = append(d.results, convertRuleResult(eval))
	}

	return d.results, nil
}

// SetRunner allows tests to inject custom runner.
func (d *DatabaseChecker) SetRunner(r *engine.Runner) {
	d.runner = r
}
