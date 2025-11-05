//go:build linux || windows || darwin

package benchmark

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"time"

	"github.com/m-sec-org/d-eyes/agent/internal/progress"
)

// benchmarkScanner 实现Scanner接口的扫描器
type benchmarkScanner struct {
	checkers []BenchmarkChecker
	config   Config
	stats    map[string]interface{}
	progress *progress.Manager
}

// NewScanner 创建新的扫描器实例
func NewScanner(config ...Config) Scanner {
	var cfg Config
	if len(config) > 0 {
		cfg = config[0]
	}
	return &benchmarkScanner{
		checkers: make([]BenchmarkChecker, 0),
		config:   cfg,
		stats:    make(map[string]interface{}),
	}
}

// AddChecker 添加检查器
func (s *benchmarkScanner) AddChecker(checker BenchmarkChecker) {
	// 检查平台兼容性
	platforms := checker.GetSupportedPlatforms()
	currentPlatform := runtime.GOOS
	platformSupported := false

	for _, p := range platforms {
		if p == currentPlatform || p == "all" {
			platformSupported = true
			break
		}
	}

	if !platformSupported {
		fmt.Printf("警告: %s 检查器不支持当前平台 %s，将被跳过\n", checker.GetName(), currentPlatform)
		return
	}

	s.checkers = append(s.checkers, checker)
}

// SetProgress 设置进度管理器
func (s *benchmarkScanner) SetProgress(manager *progress.Manager) {
	s.progress = manager
}

// Scan 执行扫描
func (s *benchmarkScanner) Scan(ctx context.Context, scope string) ([]CheckResult, error) {
	startTime := time.Now()
	results := make([]CheckResult, 0)
	if s.progress != nil {
		s.progress.Debugf("开始基线检查，范围: %s", scope)
	}

	// 根据scope过滤检查器
	var filteredCheckers []BenchmarkChecker
	for _, checker := range s.checkers {
		checkerName := checker.GetName()
		if scope == "all" ||
			(scope == "os" && (checkerName == "LinuxOSChecker" || checkerName == "WindowsOSChecker")) ||
			(scope == "middleware" && (checkerName == "WebServerChecker" || checkerName == "AppServerChecker")) ||
			(scope == "database" && checkerName == "DatabaseChecker") {
			filteredCheckers = append(filteredCheckers, checker)
		}
	}

	if s.progress != nil && len(filteredCheckers) > 0 {
		s.progress.StartStage(progress.StageBenchmark, len(filteredCheckers), "初始化检查器")
	}

	readyCheckers := make([]BenchmarkChecker, 0, len(filteredCheckers))
	for _, checker := range filteredCheckers {
		if err := checker.Init(ctx); err != nil {
			fmt.Printf("初始化 %s 失败: %v\n", checker.GetName(), err)
			if s.progress != nil {
				s.progress.Add(progress.StageBenchmark, 1, fmt.Sprintf("%s 初始化失败: %v", checker.GetName(), err))
			}
			continue
		}
		readyCheckers = append(readyCheckers, checker)
		if s.progress != nil {
			s.progress.Add(progress.StageBenchmark, 1, fmt.Sprintf("%s 初始化成功", checker.GetName()))
		}
	}
	filteredCheckers = readyCheckers

	if s.progress != nil && len(filteredCheckers) > 0 {
		s.progress.StartStage(progress.StageBenchmarkChecks, len(filteredCheckers), "执行检查")
	}

	// 使用WaitGroup并发执行检查
	var wg sync.WaitGroup
	resultChan := make(chan []CheckResult, len(filteredCheckers))
	errChan := make(chan error, len(filteredCheckers))

	for _, checker := range filteredCheckers {
		wg.Add(1)
		go func(c BenchmarkChecker) {
			defer wg.Done()

			checkResults, err := c.Check(ctx)
			if err != nil {
				errChan <- fmt.Errorf("%s 检查失败: %w", c.GetName(), err)
				if s.progress != nil {
					s.progress.Add(progress.StageBenchmarkChecks, 1, fmt.Sprintf("%s 检查失败: %v", c.GetName(), err))
				}
				return
			}
			resultChan <- checkResults
			if s.progress != nil {
				s.progress.Add(progress.StageBenchmarkChecks, 1, fmt.Sprintf("%s 检查完成，生成 %d 条结果", c.GetName(), len(checkResults)))
			}
		}(checker)
	}

	// 等待所有检查完成
	wg.Wait()
	close(resultChan)
	close(errChan)

	// 收集结果
	for checkResults := range resultChan {
		results = append(results, checkResults...)
	}

	// 收集错误
	for err := range errChan {
		fmt.Printf("检查错误: %v\n", err)
	}

	// 更新统计信息
	endTime := time.Now()
	s.updateStatistics(results, startTime, endTime)
	if s.progress != nil {
		s.progress.Debugf("基线检查完成，共执行 %d 个检查器", len(filteredCheckers))
	}

	return results, nil
}

// GetStatistics 获取扫描统计信息
func (s *benchmarkScanner) GetStatistics() map[string]interface{} {
	return s.stats
}

// updateStatistics 更新统计信息
func (s *benchmarkScanner) updateStatistics(results []CheckResult, startTime, endTime time.Time) {
	totalChecks := len(results)
	passedChecks := 0
	failedChecks := 0
	warningChecks := 0
	errorChecks := 0

	severityCounts := make(map[SeverityLevel]int)
	severityCounts[SeverityLow] = 0
	severityCounts[SeverityMedium] = 0
	severityCounts[SeverityHigh] = 0
	severityCounts[SeverityCritical] = 0

	for _, result := range results {
		switch result.Status {
		case StatusPass:
			passedChecks++
		case StatusFail:
			failedChecks++
		case StatusWarn:
			warningChecks++
		case StatusError:
			errorChecks++
		}

		// 更新风险级别统计
		if count, exists := severityCounts[result.Severity]; exists {
			severityCounts[result.Severity] = count + 1
		} else {
			severityCounts[result.Severity] = 1
		}
	}

	summary := ResultSummary{
		TotalChecks:    totalChecks,
		PassedChecks:   passedChecks,
		FailedChecks:   failedChecks,
		WarningChecks:  warningChecks,
		ErrorChecks:    errorChecks,
		SeverityCounts: severityCounts,
		StartTime:      startTime,
		EndTime:        endTime,
		Duration:       endTime.Sub(startTime).Seconds(),
	}

	s.stats["summary"] = summary
	s.stats["total_checkers"] = len(s.checkers)
	s.stats["platform"] = runtime.GOOS
}
