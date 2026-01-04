package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/urfave/cli/v2"

	internal "github.com/m-sec-org/d-eyes/agent/internal"
	"github.com/m-sec-org/d-eyes/agent/internal/collector"
	"github.com/m-sec-org/d-eyes/agent/internal/debugger"
)

func ensureCollectCommand(app *cli.App) {
	for _, cmd := range app.Commands {
		if cmd.Name == "collect" {
			return
		}
	}
	internal.AttachCommand(app, collectCommand())
}

func collectCommand() *cli.Command {
	return &cli.Command{
		Name:     "collect",
		Usage:    "运行配置文件中的系统事件采集器（ETW/eBPF），支持 --debug 时实时输出并写入调试时间线（默认保存于 <output-dir>/collect/debug-timeline-*.json）",
		Category: "Integration",
		Flags: []cli.Flag{
			&cli.DurationFlag{
				Name:  "duration",
				Usage: "运行指定时间后自动退出（默认持续运行，按 Ctrl+C 停止）",
			},
			&cli.StringSliceFlag{
				Name:  "collector",
				Usage: "仅运行指定名称的采集器，可重复设置",
			},
			&cli.StringSliceFlag{
				Name:  "backend",
				Usage: "按采集器类型过滤（etw/ebpf 等），可重复设置",
			},
			&cli.StringSliceFlag{
				Name:  "providers",
				Usage: "覆盖 ETW Provider（GUID 或名称），可重复设置",
			},
			&cli.StringSliceFlag{
				Name:  "probes",
				Usage: "覆盖 eBPF Probe 名称，可重复设置",
			},
			&cli.StringFlag{
				Name:  "output-mode",
				Usage: "覆盖 Collector 输出模式（stdout/file/stream）",
			},
			&cli.StringFlag{
				Name:  "output-path",
				Usage: "覆盖 Collector 输出路径（file 模式）",
			},
			&cli.StringFlag{
				Name:  "stream-url",
				Usage: "覆盖 stream 输出 URL（当 output-mode=stream 时）",
			},
			&cli.StringFlag{
				Name:  "stream-api-key",
				Usage: "覆盖 stream 输出认证 token",
			},
			&cli.StringFlag{
				Name:  "stream-agent-id",
				Usage: "覆盖 stream 输出使用的 agent_id",
			},
			&cli.StringFlag{
				Name:  "stream-agent-name",
				Usage: "覆盖 stream 输出使用的 agent_name",
			},
			&cli.IntFlag{
				Name:  "stream-max-batch",
				Usage: "覆盖 stream 输出单批事件数",
			},
			&cli.DurationFlag{
				Name:  "stream-flush",
				Usage: "覆盖 stream 输出 flush 间隔",
			},
		},
		Action: runCollectCommand,
	}
}

func runCollectCommand(c *cli.Context) error {
	emitter := debugger.NewEmitter(os.Stderr, c.Bool("debug"))
	cfg := internal.GetGlobalConfig()
	defs := collector.FromAppConfig(cfg)
	selected := normalizeCollectorFilters(c.StringSlice("collector"))
	if len(selected) > 0 {
		defs = filterCollectorConfigs(defs, selected)
	}
	kinds := normalizeCollectorFilters(c.StringSlice("backend"))
	if len(kinds) > 0 {
		defs = filterCollectorsByKind(defs, kinds)
	}
	expectedActive := countEnabledCollectors(defs)
	if len(defs) == 0 {
		overrides := collectCLIOverridesFromContext(c)
		adhoc := buildAdhocCollectors(overrides, kinds)
		if len(adhoc) > 0 {
			defs = adhoc
			expectedActive = len(adhoc)
		}
	}
	if len(defs) == 0 {
		return cli.Exit("未找到任何可运行的采集器，请在配置文件中定义 collectors 或使用 --backend/--probes/--providers 参数", 1)
	}
	opts := []collector.ServiceOption{}
	if hook := collectorServiceOptionsHook; hook != nil {
		opts = append(opts, hook()...)
	}
	if emitter.Enabled() {
		opts = append(opts, collector.WithDebugEmitter(emitter))
	}
	service := collector.NewService(defs, opts...)
	ctx, cancel := context.WithCancel(c.Context)
	defer cancel()

	handler := newConsoleEventHandler()
	if emitter.Enabled() {
		backendLabel := strings.Join(normalizeCollectorFilters(c.StringSlice("backend")), "+")
		handler = &statsHandler{base: handler, emitter: emitter, backend: backendLabel}
	}
	if emitter.Enabled() {
		emitter.PhaseStart("collect", "start", fmt.Sprintf("expected=%d", expectedActive))
	}
	if err := service.Start(ctx, handler); err != nil {
		return cli.Exit(fmt.Sprintf("采集器启动失败: %v", err), 1)
	}
	defer func() {
		stopCtx, stopCancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer stopCancel()
		if err := service.Stop(stopCtx); err != nil {
			fmt.Fprintf(os.Stderr, "停止采集器失败: %v\n", err)
		}
	}()

	statusSnapshot := waitForCollectorStartup(func() []collector.CollectorStatus {
		return service.Status()
	}, expectedActive, 5*time.Second, emitter)
	printCollectorStatus(statusSnapshot)
	if running := countRunningCollectors(statusSnapshot); expectedActive > 0 && running < expectedActive {
		fmt.Fprintf(os.Stderr, "警告：仅有 %d/%d 个采集器处于运行状态，请检查 LastError 或日志输出。\n", running, expectedActive)
	}
	fmt.Println("采集器已启动，按 Ctrl+C 停止。")
	if err := waitForCollectorStop(ctx, c.Duration("duration")); err != nil && err != context.Canceled {
		return cli.Exit(err.Error(), 1)
	}
	fmt.Println("采集器已停止。")
	if emitter.Enabled() {
		emitter.PhaseEnd("collect", "stopped")
		if path, err := persistCollectDebugTimeline(emitter, cfg.Output.Dir); err != nil {
			fmt.Fprintf(os.Stderr, "[debug] 调试时间线写入失败: %v\n", err)
		} else if path != "" {
			fmt.Fprintf(os.Stderr, "[debug] 调试时间线已写入 %s\n", path)
		}
	}
	return nil
}

// collectorServiceOptionsHook allows tests to inject custom ServiceOptions.
var collectorServiceOptionsHook func() []collector.ServiceOption

func newConsoleEventHandler() collector.EventHandler {
	var mu sync.Mutex
	return collector.EventHandlerFunc(func(_ context.Context, event *collector.SystemEvent) error {
		if event == nil {
			return nil
		}
		data, err := json.Marshal(event)
		if err != nil {
			return err
		}
		mu.Lock()
		defer mu.Unlock()
		fmt.Println(string(data))
		return nil
	})
}

func waitForCollectorStop(ctx context.Context, duration time.Duration) error {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)

	var timer <-chan time.Time
	if duration > 0 {
		timer = time.After(duration)
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-signals:
		return nil
	case <-timer:
		return nil
	}
}

func filterCollectorConfigs(configs []collector.Config, names []string) []collector.Config {
	if len(names) == 0 {
		return configs
	}
	nameSet := make(map[string]struct{}, len(names))
	for _, name := range names {
		if trimmed := strings.TrimSpace(name); trimmed != "" {
			nameSet[trimmed] = struct{}{}
		}
	}
	if len(nameSet) == 0 {
		return configs
	}
	filtered := make([]collector.Config, 0, len(configs))
	for _, cfg := range configs {
		if _, ok := nameSet[cfg.Name]; ok {
			filtered = append(filtered, cfg)
		}
	}
	return filtered
}

func normalizeCollectorFilters(values []string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		for _, part := range strings.Split(value, ",") {
			if trimmed := strings.TrimSpace(part); trimmed != "" {
				result = append(result, trimmed)
			}
		}
	}
	return result
}

func persistCollectDebugTimeline(emitter *debugger.Emitter, baseDir string) (string, error) {
	if emitter == nil {
		return "", nil
	}
	events := emitter.Events()
	if len(events) == 0 {
		return "", nil
	}
	dir := strings.TrimSpace(baseDir)
	if dir == "" {
		dir = filepath.Join(os.TempDir(), "d-eyes", "collect")
	} else {
		dir = filepath.Join(dir, "collect")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	timestamp := time.Now().Format("20060102-150405")
	path := filepath.Join(dir, fmt.Sprintf("debug-timeline-%s.json", timestamp))
	file, err := os.Create(path)
	if err != nil {
		return "", err
	}
	enc := json.NewEncoder(file)
	enc.SetIndent("", "  ")
	if err := enc.Encode(events); err != nil {
		file.Close()
		return "", err
	}
	file.Close()
	if meta := emitter.Metadata(); len(meta) > 0 {
		metaPath := filepath.Join(dir, fmt.Sprintf("debug-summary-%s.json", timestamp))
		metaFile, err := os.Create(metaPath)
		if err == nil {
			menc := json.NewEncoder(metaFile)
			menc.SetIndent("", "  ")
			_ = menc.Encode(meta)
			metaFile.Close()
		}
	}
	return path, nil
}

func filterCollectorsByKind(configs []collector.Config, kinds []string) []collector.Config {
	if len(kinds) == 0 {
		return configs
	}
	kindSet := make(map[string]struct{}, len(kinds))
	for _, k := range kinds {
		if trimmed := strings.TrimSpace(strings.ToLower(k)); trimmed != "" {
			kindSet[trimmed] = struct{}{}
		}
	}
	if len(kindSet) == 0 {
		return configs
	}
	filtered := make([]collector.Config, 0, len(configs))
	for _, cfg := range configs {
		if _, ok := kindSet[strings.ToLower(string(cfg.Kind))]; ok {
			filtered = append(filtered, cfg)
		}
	}
	return filtered
}

type collectCLIOverrides struct {
	providers []string
	probes    []string
	output    collector.Output
}

type statsHandler struct {
	base    collector.EventHandler
	mu      sync.Mutex
	count   int
	last    time.Time
	backend string
	emitter *debugger.Emitter
}

func (s *statsHandler) HandleEvent(ctx context.Context, event *collector.SystemEvent) error {
	if s == nil {
		return nil
	}
	if s.emitter != nil {
		s.mu.Lock()
		s.count++
		now := time.Now()
		if s.last.IsZero() {
			s.last = now
		}
		elapsed := now.Sub(s.last)
		if s.count%100 == 0 || elapsed >= time.Second {
			rate := float64(s.count) / elapsed.Seconds()
			label := "collect.stats"
			if s.backend != "" {
				label = label + "." + s.backend
			}
			s.emitter.Notice(label, fmt.Sprintf("events=%d rate=%.1f/s", s.count, rate))
			s.last = now
		}
		s.mu.Unlock()
	}
	if s.base == nil {
		return nil
	}
	return s.base.HandleEvent(ctx, event)
}

func collectCLIOverridesFromContext(c *cli.Context) collectCLIOverrides {
	mode := strings.TrimSpace(strings.ToLower(c.String("output-mode")))
	path := strings.TrimSpace(c.String("output-path"))
	stream := collector.CollectorStreamConfig{
		URL:           strings.TrimSpace(c.String("stream-url")),
		APIKey:        strings.TrimSpace(c.String("stream-api-key")),
		AgentID:       strings.TrimSpace(c.String("stream-agent-id")),
		AgentName:     strings.TrimSpace(c.String("stream-agent-name")),
		MaxBatch:      c.Int("stream-max-batch"),
		FlushInterval: c.Duration("stream-flush"),
	}
	output := collector.Output{
		Mode:   mode,
		Path:   path,
		Stream: stream,
	}
	return collectCLIOverrides{
		providers: normalizeCollectorFilters(c.StringSlice("providers")),
		probes:    normalizeCollectorFilters(c.StringSlice("probes")),
		output:    output,
	}
}

func buildAdhocCollectors(overrides collectCLIOverrides, kinds []string) []collector.Config {
	if len(kinds) == 0 {
		return nil
	}
	configs := make([]collector.Config, 0, len(kinds))
	seen := make(map[string]struct{})
	for _, raw := range kinds {
		kind := strings.TrimSpace(strings.ToLower(raw))
		if kind == "" {
			continue
		}
		if _, ok := seen[kind]; ok {
			continue
		}
		seen[kind] = struct{}{}
		cfg := collector.Config{
			Name:   fmt.Sprintf("cli-%s", kind),
			Kind:   collector.Kind(kind),
			Output: overrides.output,
		}
		switch kind {
		case string(collector.KindEBPF):
			cfg.Kind = collector.KindEBPF
			if len(overrides.probes) > 0 {
				cfg.Probes = append([]string(nil), overrides.probes...)
			}
		case string(collector.KindETW):
			cfg.Kind = collector.KindETW
			if len(overrides.providers) > 0 {
				cfg.Providers = append([]string(nil), overrides.providers...)
			}
		default:
			continue
		}
		configs = append(configs, cfg)
	}
	return configs
}

func countEnabledCollectors(configs []collector.Config) int {
	count := 0
	for _, cfg := range configs {
		if cfg.Disabled {
			continue
		}
		count++
	}
	return count
}

func waitForCollectorStartup(statusFn func() []collector.CollectorStatus, expected int, timeout time.Duration, emitter *debugger.Emitter) []collector.CollectorStatus {
	if expected <= 0 {
		snapshot := statusFn()
		emitCollectorStartupProgress(emitter, countRunningCollectors(snapshot), expected)
		return snapshot
	}
	deadline := time.Now().Add(timeout)
	var snapshot []collector.CollectorStatus
	for {
		snapshot = statusFn()
		running := countRunningCollectors(snapshot)
		emitCollectorStartupProgress(emitter, running, expected)
		if running >= expected {
			break
		}
		if time.Now().After(deadline) {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	emitCollectorStartupProgress(emitter, countRunningCollectors(snapshot), expected)
	return snapshot
}

func emitCollectorStartupProgress(emitter *debugger.Emitter, running, expected int) {
	if emitter == nil || expected <= 0 {
		return
	}
	if running > expected {
		running = expected
	}
	emitter.Progress("collect.startup", running, expected, fmt.Sprintf("collectors running: %d/%d", running, expected))
}

func countRunningCollectors(status []collector.CollectorStatus) int {
	count := 0
	for _, st := range status {
		if strings.EqualFold(st.State, "running") {
			count++
		}
	}
	return count
}

func printCollectorStatus(status []collector.CollectorStatus) {
	if len(status) == 0 {
		fmt.Println("当前没有运行中的采集器")
		return
	}
	fmt.Println("运行中的采集器：")
	for _, st := range status {
		fmt.Printf(" - %s (%s): %s\n", st.Name, st.Kind, st.State)
		if st.LastError != "" {
			fmt.Printf("   上次错误: %s\n", st.LastError)
		}
	}
}
