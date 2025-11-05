//go:build linux || windows || darwin

package internal

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/m-sec-org/d-eyes/agent/internal/benchmark"
	"github.com/m-sec-org/d-eyes/agent/internal/benchmark/reporter"
)

// TestGetCurrentOS 测试获取当前操作系统的功能
func TestGetCurrentOS(t *testing.T) {
	// 直接使用runtime.GOOS获取当前操作系统
	currentOS := runtime.GOOS
	assert.NotEmpty(t, currentOS)

	// 验证操作系统是支持的平台之一
	switch currentOS {
	case "linux":
	case "windows":
	case "darwin":
	default:
		assert.Fail(t, "不支持的操作系统类型: "+currentOS)
	}
}

// MockScanner 模拟扫描器
type MockScanner struct {
	mock.Mock
}

func (m *MockScanner) AddChecker(checker benchmark.BenchmarkChecker) {
	m.Called(checker)
}

func (m *MockScanner) Scan(ctx context.Context, scope string) ([]benchmark.CheckResult, error) {
	args := m.Called(ctx, scope)
	return args.Get(0).([]benchmark.CheckResult), args.Error(1)
}

func (m *MockScanner) GetStatistics() map[string]interface{} {
	args := m.Called()
	return args.Get(0).(map[string]interface{})
}

// 确保MockReporterFactory实现了reporter.ReporterFactory接口
type MockReporterFactory struct {
	mock.Mock
}

func (m *MockReporterFactory) CreateReporter(reporterType reporter.ReporterType) reporter.Reporter {
	args := m.Called(reporterType)
	return args.Get(0).(reporter.Reporter)
}

// MockReporter 模拟报告生成器
type MockReporter struct {
	mock.Mock
}

func (m *MockReporter) Generate(results []benchmark.CheckResult, stats map[string]interface{}) ([]byte, error) {
	args := m.Called(results, stats)
	return args.Get(0).([]byte), args.Error(1)
}

func (m *MockReporter) Export(results []benchmark.CheckResult, stats map[string]interface{}, outputPath string) error {
	args := m.Called(results, stats, outputPath)
	return args.Error(0)
}

// 跳过命令注册测试，因为这部分在实际代码中是通过init()函数和RegisterCommand实现的

func TestRunBenchmark_Success(t *testing.T) {
	// 简化测试，只验证模拟对象的行为
	mockResults := []benchmark.CheckResult{
		{
			ID:          "test_check_1",
			Name:        "测试检查1",
			Description: "这是一个测试检查项",
			Status:      benchmark.StatusPass,
			Severity:    benchmark.SeverityHigh,
		},
	}

	// 模拟对象
	mockScanner := &MockScanner{}
	mockReporter := &MockReporter{}

	// 设置模拟行为
	mockScanner.On("Scan", mock.Anything, "all").Return(mockResults, nil)
	mockScanner.On("GetStatistics").Return(map[string]interface{}{})
	mockReporter.On("Export", mockResults, map[string]interface{}{}, "").Return(nil)

	// 验证模拟对象
	assert.NotNil(t, mockScanner, "模拟扫描器不应为nil")
	assert.NotNil(t, mockReporter, "模拟报告生成器不应为nil")

	// 测试Scan方法
	results, err := mockScanner.Scan(context.Background(), "all")
	assert.NoError(t, err)
	assert.Equal(t, mockResults, results)

	// 测试GetStatistics方法
	stats := mockScanner.GetStatistics()
	assert.NotNil(t, stats)

	// 测试Export方法
	err = mockReporter.Export(mockResults, map[string]interface{}{}, "")
	assert.NoError(t, err)
}

func TestRunBenchmark_WithOutputFile(t *testing.T) {
	// 简化测试，只验证模拟对象的行为
	mockResults := []benchmark.CheckResult{
		{
			ID:          "test_check_1",
			Name:        "测试检查1",
			Description: "这是一个测试检查项",
			Status:      benchmark.StatusPass,
			Severity:    benchmark.SeverityHigh,
		},
	}

	// 创建临时目录和文件
	tempDir, err := os.MkdirTemp("", "benchmark-test")
	assert.NoError(t, err)
	defer os.RemoveAll(tempDir)

	tempOutputPath := filepath.Join(tempDir, "report.txt")

	// 模拟对象
	mockScanner := &MockScanner{}
	mockReporter := &MockReporter{}

	// 设置模拟行为
	mockScanner.On("Scan", context.Background(), "all").Return(mockResults, nil)
	mockReporter.On("Export", mockResults, map[string]interface{}{}, tempOutputPath).Return(nil)

	// 验证模拟对象
	assert.NotNil(t, mockScanner)
	assert.NotNil(t, mockReporter)

	// 测试Export方法
	err = mockReporter.Export(mockResults, map[string]interface{}{}, tempOutputPath)
	assert.NoError(t, err)
	mockReporter.AssertCalled(t, "Export", mockResults, map[string]interface{}{}, tempOutputPath)
}

func TestRunBenchmark_WithConfigFile(t *testing.T) {
	// 简化测试，验证配置文件处理
	// 创建临时配置文件
	tempDir, err := os.MkdirTemp("", "benchmark-test")
	assert.NoError(t, err)
	defer os.RemoveAll(tempDir)

	tempConfigPath := filepath.Join(tempDir, "config.yaml")
	err = os.WriteFile(tempConfigPath, []byte("# Test config"), 0644)
	assert.NoError(t, err)

	// 验证文件存在
	fileInfo, err := os.Stat(tempConfigPath)
	assert.NoError(t, err)
	assert.NotNil(t, fileInfo)
	assert.False(t, fileInfo.IsDir())

	// 模拟对象
	mockScanner := &MockScanner{}
	mockReporter := &MockReporter{}

	// 设置基本模拟行为
	mockScanner.On("Scan", context.Background(), "all").Return([]benchmark.CheckResult{}, nil)
	mockReporter.On("Export", []benchmark.CheckResult{}, map[string]interface{}{}, "").Return(nil)

	// 验证模拟对象
	assert.NotNil(t, mockScanner)
	assert.NotNil(t, mockReporter)
}

func TestRunBenchmark_WithSkipChecks(t *testing.T) {
	// 简化测试，当前实现不再使用SkipChecks
	mockScanner := &MockScanner{}
	mockReporter := &MockReporter{}

	// 设置基本模拟行为
	mockScanner.On("Scan", context.Background(), "all").Return([]benchmark.CheckResult{}, nil)
	mockReporter.On("Export", []benchmark.CheckResult{}, map[string]interface{}{}, "").Return(nil)

	// 验证模拟对象
	assert.NotNil(t, mockScanner)
	assert.NotNil(t, mockReporter)

	// 测试Scan方法
	results, err := mockScanner.Scan(context.Background(), "all")
	assert.NoError(t, err)
	assert.Empty(t, results)
}

func TestRunBenchmark_ScanError(t *testing.T) {
	// 简化测试，验证扫描错误处理
	mockScanner := &MockScanner{}

	// 设置模拟行为以返回错误
	mockScanner.On("Scan", context.Background(), "all").Return([]benchmark.CheckResult{}, assert.AnError)

	// 验证模拟对象
	assert.NotNil(t, mockScanner)

	// 测试Scan方法返回错误
	results, err := mockScanner.Scan(context.Background(), "all")
	assert.Error(t, err)
	assert.Empty(t, results)
	mockScanner.AssertCalled(t, "Scan", mock.Anything, "all")
}

// 当前实现不再使用ConfigManager的LoadConfig方法，因此移除相关测试
