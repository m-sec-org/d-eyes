package telemetry

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"sync"
	"sync/atomic"
	"time"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/mem"
)

// SystemSamplerFunc 抽象系统采样调度逻辑，便于测试替换。
type SystemSamplerFunc func(context.Context, time.Duration)

// MetadataCollector 定义执行元数据的采集行为。
type MetadataCollector func(context.Context) map[string]string

// CPUPercentProvider 返回当前 CPU 百分比。
type CPUPercentProvider func() float64

// MemoryPercentProvider 返回当前内存占用比例。
type MemoryPercentProvider func() float64

// IOUtilizationProvider 返回当前 IO 利用率。
type IOUtilizationProvider func() float64

// BlockedActionsProvider 返回当前阻断操作列表。
type BlockedActionsProvider func() []string

var (
	samplerMu sync.RWMutex
	sampler   SystemSamplerFunc = defaultSystemSampler

	metadataMu        sync.RWMutex
	metadataCollector MetadataCollector = defaultMetadataCollector

	cpuProviderMu sync.RWMutex
	cpuProvider   CPUPercentProvider = defaultCPUPercentProvider

	memoryProviderMu sync.RWMutex
	memoryProvider   MemoryPercentProvider = defaultMemoryPercentProvider

	blockedProviderMu sync.RWMutex
	blockedProvider   BlockedActionsProvider = defaultBlockedActionsProvider

	cpuSample atomic.Value
	memSample atomic.Value
)

func init() {
	cpuSample.Store(float64(0))
	memSample.Store(float64(0))
}

// StartSystemSampler 启动系统指标采样任务。
func StartSystemSampler(ctx context.Context, interval time.Duration) {
	samplerMu.RLock()
	fn := sampler
	samplerMu.RUnlock()
	fn(ctx, interval)
}

// LatestCPUPercent 返回最近一次采样记录的 CPU 利用率。
func LatestCPUPercent() float64 {
	cpuProviderMu.RLock()
	fn := cpuProvider
	cpuProviderMu.RUnlock()
	return fn()
}

// LatestMemoryPercent 返回最近一次采样记录的内存利用率。
func LatestMemoryPercent() float64 {
	memoryProviderMu.RLock()
	fn := memoryProvider
	memoryProviderMu.RUnlock()
	return fn()
}

// CurrentBlockedActions 返回当前被阻断的动作列表。
func CurrentBlockedActions() []string {
	blockedProviderMu.RLock()
	fn := blockedProvider
	blockedProviderMu.RUnlock()
	actions := fn()
	if len(actions) == 0 {
		return nil
	}
	return append([]string(nil), actions...)
}

// CollectExecutionMetadata 汇总执行期元数据。
func CollectExecutionMetadata(ctx context.Context) map[string]string {
	metadataMu.RLock()
	collector := metadataCollector
	metadataMu.RUnlock()
	if collector == nil {
		return nil
	}
	raw := collector(ctx)
	if len(raw) == 0 {
		return nil
	}
	result := make(map[string]string, len(raw))
	for k, v := range raw {
		result[k] = v
	}
	return result
}

// OverrideSystemSampler 替换系统采样逻辑，返回恢复函数（仅测试使用）。
func OverrideSystemSampler(fn SystemSamplerFunc) func() {
	samplerMu.Lock()
	prev := sampler
	if fn == nil {
		fn = defaultSystemSampler
	}
	sampler = fn
	samplerMu.Unlock()
	return func() {
		samplerMu.Lock()
		sampler = prev
		samplerMu.Unlock()
	}
}

// OverrideExecutionMetadataCollector 替换执行元数据采集器，返回恢复函数。
func OverrideExecutionMetadataCollector(collector MetadataCollector) func() {
	metadataMu.Lock()
	prev := metadataCollector
	if collector == nil {
		collector = defaultMetadataCollector
	}
	metadataCollector = collector
	metadataMu.Unlock()
	return func() {
		metadataMu.Lock()
		metadataCollector = prev
		metadataMu.Unlock()
	}
}

// OverrideCPUPercentProvider 替换 CPU 采样提供者，返回恢复函数。
func OverrideCPUPercentProvider(provider CPUPercentProvider) func() {
	cpuProviderMu.Lock()
	prev := cpuProvider
	if provider == nil {
		provider = defaultCPUPercentProvider
	}
	cpuProvider = provider
	cpuProviderMu.Unlock()
	return func() {
		cpuProviderMu.Lock()
		cpuProvider = prev
		cpuProviderMu.Unlock()
	}
}

// OverrideMemoryPercentProvider 替换内存利用率提供者。
func OverrideMemoryPercentProvider(provider MemoryPercentProvider) func() {
	memoryProviderMu.Lock()
	prev := memoryProvider
	if provider == nil {
		provider = defaultMemoryPercentProvider
	}
	memoryProvider = provider
	memoryProviderMu.Unlock()
	return func() {
		memoryProviderMu.Lock()
		memoryProvider = prev
		memoryProviderMu.Unlock()
	}
}

// OverrideBlockedActionsProvider 替换阻断动作提供者，返回恢复函数。
func OverrideBlockedActionsProvider(provider BlockedActionsProvider) func() {
	blockedProviderMu.Lock()
	prev := blockedProvider
	if provider == nil {
		provider = defaultBlockedActionsProvider
	}
	blockedProvider = provider
	blockedProviderMu.Unlock()
	return func() {
		blockedProviderMu.Lock()
		blockedProvider = prev
		blockedProviderMu.Unlock()
	}
}

// BAStepTelemetry 描述 BAS 步骤执行详情。
type BAStepTelemetry struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	Status     string    `json:"status"`
	ExitCode   int       `json:"exit_code"`
	Sandbox    bool      `json:"sandbox"`
	Sandboxed  bool      `json:"sandboxed"`
	Fallback   bool      `json:"fallback"`
	Severity   string    `json:"severity,omitempty"`
	DurationMs int64     `json:"duration_ms"`
	StartedAt  time.Time `json:"started_at"`
	EndedAt    time.Time `json:"ended_at"`
}

// SandboxStats 汇总沙箱运行指标。
type SandboxStats struct {
	Enabled        bool `json:"enabled"`
	Required       bool `json:"required"`
	Approved       bool `json:"approved"`
	StepsSandboxed int  `json:"steps_sandboxed"`
	Fallbacks      int  `json:"fallbacks"`
	TotalSteps     int  `json:"total_steps"`
}

// EncodeBASteps 将步骤遥测压缩并编码为 base64 字符串。
func EncodeBASteps(steps []BAStepTelemetry) (string, error) {
	if len(steps) == 0 {
		return "", nil
	}
	return encodePayload(steps)
}

// EncodeSandboxStats 编码沙箱统计。
func EncodeSandboxStats(stats SandboxStats) (string, error) {
	return encodePayload(stats)
}

func encodePayload(payload any) (string, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	writer := gzip.NewWriter(&buf)
	if _, err := writer.Write(data); err != nil {
		return "", err
	}
	if err := writer.Close(); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}

func defaultSystemSampler(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 5 * time.Second
	}
	ticker := time.NewTicker(interval)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				refreshCPUPercent()
				refreshMemoryPercent()
				refreshIOStats()
			}
		}
	}()
}

func refreshCPUPercent() {
	values, err := cpu.Percent(0, false)
	if err != nil || len(values) == 0 {
		return
	}
	cpuSample.Store(values[0])
}

func refreshMemoryPercent() {
	vm, err := mem.VirtualMemory()
	if err != nil || vm == nil {
		return
	}
	memSample.Store(vm.UsedPercent)
}

func defaultCPUPercentProvider() float64 {
	val, _ := cpuSample.Load().(float64)
	return val
}

func defaultMemoryPercentProvider() float64 {
	val, _ := memSample.Load().(float64)
	return val
}

var ioSample atomic.Value
var (
	ioProviderMu sync.RWMutex
	ioProvider   IOUtilizationProvider = defaultIOUtilizationProvider
)

func init() {
	ioSample.Store(float64(0))
}

func refreshIOStats() {
	counters, err := disk.IOCounters()
	if err != nil || len(counters) == 0 {
		return
	}
	var maxUtil float64
	for _, c := range counters {
		if c.IoTime > 0 && c.WeightedIO > 0 {
			util := float64(c.WeightedIO) / 10.0 // rough util percent approximation
			if util > maxUtil {
				maxUtil = util
			}
		}
	}
	ioSample.Store(maxUtil)
}

// LatestIOUtilization 近似返回最近一次磁盘 IO 利用率 (0-100)。
func LatestIOUtilization() float64 {
	ioProviderMu.RLock()
	fn := ioProvider
	ioProviderMu.RUnlock()
	return fn()
}

// OverrideIOUtilizationProvider 替换 IO 利用率提供者。
func OverrideIOUtilizationProvider(provider IOUtilizationProvider) func() {
	ioProviderMu.Lock()
	prev := ioProvider
	if provider == nil {
		provider = defaultIOUtilizationProvider
	}
	ioProvider = provider
	ioProviderMu.Unlock()
	return func() {
		ioProviderMu.Lock()
		ioProvider = prev
		ioProviderMu.Unlock()
	}
}

func defaultMetadataCollector(context.Context) map[string]string {
	return nil
}

func defaultBlockedActionsProvider() []string {
	return nil
}

func defaultIOUtilizationProvider() float64 {
	val, _ := ioSample.Load().(float64)
	return val
}
