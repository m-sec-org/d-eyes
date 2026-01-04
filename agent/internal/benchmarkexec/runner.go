//go:build linux || windows || darwin

package benchmarkexec

import (
	"context"
	"runtime"
	"strings"
	"time"

	"github.com/m-sec-org/d-eyes/agent/internal/benchmark"
	"github.com/m-sec-org/d-eyes/agent/internal/benchmark/checkers"
	"github.com/m-sec-org/d-eyes/agent/internal/benchmark/config"
	"github.com/m-sec-org/d-eyes/agent/internal/progress"
)

// Request 描述基线检查请求
type Request struct {
	Scope      string
	ConfigPath string
	Timeout    time.Duration
	Verbose    bool
	Debug      bool
	Reporter   progress.Reporter
}

// Result 包含扫描后的详细信息
type Result struct {
	Checks        []benchmark.CheckResult
	SeverityCount map[string]int
	Duration      time.Duration
	Warnings      []string
}

// Execute 执行基线检查
func Execute(ctx context.Context, req Request) (Result, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if req.Scope == "" {
		req.Scope = "all"
	}
	if req.Timeout <= 0 {
		req.Timeout = 5 * time.Minute
	}

	configManager := config.NewConfigManager()
	var warnings []string
	if err := configManager.LoadConfig(req.ConfigPath); err != nil {
		warnings = append(warnings, err.Error())
	}

	cfg := benchmark.Config{
		Timeout: int(req.Timeout.Seconds()),
		Verbose: req.Verbose,
		Debug:   req.Debug,
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = int((5 * time.Minute).Seconds())
	}

	scanner := benchmark.NewScanner(cfg)
	reporter := req.Reporter
	if reporter == nil {
		reporter = progress.NullReporter{}
	}
	progressManager := progress.NewManager(reporter, 500*time.Millisecond, cfg.Debug)
	scanner.SetProgress(progressManager)
	defer progressManager.Finish()

	registerCheckers(scanner, cfg)

	ctxTimeout, cancel := context.WithTimeout(ctx, req.Timeout)
	defer cancel()

	start := time.Now()
	checks, err := scanner.Scan(ctxTimeout, req.Scope)
	if err != nil {
		return Result{}, err
	}
	duration := time.Since(start)

	severity := make(map[string]int)
	for _, check := range checks {
		severity[strings.ToLower(string(check.Severity))]++
	}

	return Result{
		Checks:        checks,
		SeverityCount: severity,
		Duration:      duration,
		Warnings:      warnings,
	}, nil
}

func registerCheckers(scanner benchmark.Scanner, cfg benchmark.Config) {
	switch runtime.GOOS {
	case "linux":
		scanner.AddChecker(checkers.NewLinuxOSChecker(cfg))
	case "windows":
		scanner.AddChecker(checkers.NewWindowsOSChecker(cfg))
	}
	scanner.AddChecker(checkers.NewDatabaseChecker(cfg))
	scanner.AddChecker(checkers.NewWebServerChecker(cfg))
	scanner.AddChecker(checkers.NewAppServerChecker(cfg))
}
