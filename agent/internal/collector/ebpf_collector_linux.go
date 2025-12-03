//go:build linux

package collector

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"golang.org/x/sys/unix"
)

const (
	minKernelMajor = 5
	minKernelMinor = 8

	ebpfEventTypeExec = 1
	ebpfEventTypeExit = 2

	verifierLogLevelNone    ebpf.LogLevel = 0
	verifierLogLevelVerbose ebpf.LogLevel = 1
	verifierLogLevelAll     ebpf.LogLevel = 2
)

type ebpfCollector struct {
	cfg       Config
	handler   EventHandler
	stateMu   sync.RWMutex
	running   bool
	startedAt time.Time
	lastError string

	objects    *ebpfObjects
	links      []link.Link
	probeSet   []ebpfProbe
	env        ebpfEnvironment
	cancelFunc context.CancelFunc
	buildInfo  compileMetadata
	perfReader *perf.Reader
	readWG     sync.WaitGroup
	sampler    *eventSampler

	eventsEmitted     uint64
	eventsFiltered    uint64
	eventsErrored     uint64
	eventsLost        uint64
	latencyLastMicros uint64
	latencyMaxMicros  uint64
}

type perfEventStats struct {
	Emitted   uint64
	Errors    uint64
	Dropped   uint64
	LastError int64
}

type syscallEvent struct {
	Timestamp uint64
	PID       uint32
	TGID      uint32
	EventType uint32
	Aux       uint32
	Comm      [16]byte
}

// ebpfObjects hosts the maps/programs loaded from the CO-RE object.
type ebpfObjects struct {
	Events                 *ebpf.Map     `ebpf:"events"`
	EventStats             *ebpf.Map     `ebpf:"event_stats"`
	HandleSysEnterExecve   *ebpf.Program `ebpf:"handle_sys_enter_execve"`
	HandleSchedProcessExit *ebpf.Program `ebpf:"handle_sched_process_exit"`
}

func (o *ebpfObjects) Close() error {
	var err error
	if o.HandleSysEnterExecve != nil {
		err = errors.Join(err, o.HandleSysEnterExecve.Close())
		o.HandleSysEnterExecve = nil
	}
	if o.HandleSchedProcessExit != nil {
		err = errors.Join(err, o.HandleSchedProcessExit.Close())
		o.HandleSchedProcessExit = nil
	}
	if o.Events != nil {
		err = errors.Join(err, o.Events.Close())
		o.Events = nil
	}
	if o.EventStats != nil {
		err = errors.Join(err, o.EventStats.Close())
		o.EventStats = nil
	}
	return err
}

type ebpfEnvironment struct {
	KernelVersion string
	KernelMajor   int
	KernelMinor   int
	KernelPatch   int
	TraceFSPath   string
	BTFPath       string
	ClangPath     string
	Target        string
	ArchMacro     string
}

type ebpfProbe struct {
	Name       string
	TraceGroup string
	TracePoint string
	Program    string
}

var (
	defaultProbeOrder = []string{
		"sys_enter_execve",
		"sched_process_exit",
	}
	availableEBPFProbes = map[string]ebpfProbe{
		"sys_enter_execve": {
			Name:       "sys_enter_execve",
			TraceGroup: "syscalls",
			TracePoint: "sys_enter_execve",
			Program:    "handle_sys_enter_execve",
		},
		"sched_process_exit": {
			Name:       "sched_process_exit",
			TraceGroup: "sched",
			TracePoint: "sched_process_exit",
			Program:    "handle_sched_process_exit",
		},
	}
)

func newEBPFCollector(cfg Config) (EventCollector, error) {
	if runtime.GOOS != "linux" {
		return nil, fmt.Errorf("ebpf collector %q is only supported on Linux", cfg.Name)
	}
	if strings.TrimSpace(cfg.Name) == "" {
		return nil, fmt.Errorf("ebpf collector requires a non-empty name")
	}
	return &ebpfCollector{
		cfg: cfg,
	}, nil
}

func (c *ebpfCollector) Name() string {
	return fmt.Sprintf("ebpf-%s", c.cfg.Name)
}

func (c *ebpfCollector) Start(ctx context.Context, handler EventHandler) error {
	c.stateMu.Lock()
	if c.running {
		c.stateMu.Unlock()
		return nil
	}
	c.stateMu.Unlock()

	env, err := inspectEBPFEnvironment(c.cfg.Settings)
	if err != nil {
		c.setLastError(err)
		return err
	}
	probes, err := c.resolveProbes()
	if err != nil {
		c.setLastError(err)
		return err
	}

	runCtx, cancel := context.WithCancel(ctx)
	objBytes, compileMeta, err := compileEmbeddedProgram(runCtx, env, c.cfg.Settings)
	if err != nil {
		cancel()
		c.setLastError(err)
		return err
	}
	objects := &ebpfObjects{}
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(objBytes))
	if err != nil {
		cancel()
		c.setLastError(err)
		return fmt.Errorf("load ebpf spec: %w", err)
	}
	if events, ok := spec.Maps["events"]; ok {
		if events.MaxEntries == 0 {
			cpus := runtime.NumCPU()
			if cpus < 1 {
				cpus = 1
			}
			events.MaxEntries = uint32(cpus)
		}
	}
	progLogLevel := specLogLevel(c.cfg.Settings)
	progOptions := ebpf.ProgramOptions{
		LogLevel: progLogLevel,
	}
	if err := spec.LoadAndAssign(objects, &ebpf.CollectionOptions{
		Programs: progOptions,
	}); err != nil {
		cancel()
		_ = objects.Close()
		c.logVerifierError(err)
		c.setLastError(err)
		return fmt.Errorf("load ebpf objects: %w", err)
	}
	if progLogLevel != verifierLogLevelNone {
		c.logVerifierOutput(objects)
	}
	links, err := c.attachProbes(objects, probes)
	if err != nil {
		cancel()
		for _, l := range links {
			_ = l.Close()
		}
		_ = objects.Close()
		c.setLastError(err)
		return err
	}
	perfReader, err := perf.NewReader(objects.Events, perfBufferSize(c.cfg.Settings))
	if err != nil {
		cancel()
		for _, l := range links {
			_ = l.Close()
		}
		_ = objects.Close()
		c.setLastError(err)
		return fmt.Errorf("create perf reader: %w", err)
	}

	c.stateMu.Lock()
	c.handler = handler
	c.objects = objects
	c.links = links
	c.probeSet = probes
	c.env = env
	c.buildInfo = compileMeta
	c.running = true
	c.startedAt = time.Now()
	c.lastError = ""
	c.cancelFunc = cancel
	c.perfReader = perfReader
	c.sampler = newEventSampler(c.cfg.Sampling)
	atomic.StoreUint64(&c.eventsEmitted, 0)
	atomic.StoreUint64(&c.eventsFiltered, 0)
	atomic.StoreUint64(&c.eventsErrored, 0)
	atomic.StoreUint64(&c.eventsLost, 0)
	atomic.StoreUint64(&c.latencyLastMicros, 0)
	atomic.StoreUint64(&c.latencyMaxMicros, 0)
	c.stateMu.Unlock()

	c.readWG.Add(1)
	go c.consumePerfEvents(runCtx, handler, perfReader)

	go func() {
		<-runCtx.Done()
		_ = c.Stop(context.Background())
	}()

	return nil
}

func (c *ebpfCollector) Stop(context.Context) error {
	c.stateMu.Lock()
	if !c.running {
		c.stateMu.Unlock()
		return nil
	}
	cancel := c.cancelFunc
	c.cancelFunc = nil
	reader := c.perfReader
	c.perfReader = nil
	links := c.links
	c.links = nil
	objects := c.objects
	c.objects = nil
	c.running = false
	c.stateMu.Unlock()

	if cancel != nil {
		cancel()
	}
	if reader != nil {
		_ = reader.Close()
	}
	c.readWG.Wait()

	var multi error
	for _, l := range links {
		multi = errors.Join(multi, l.Close())
	}
	if objects != nil {
		multi = errors.Join(multi, objects.Close())
	}
	return multi
}

func (c *ebpfCollector) Status() CollectorStatus {
	c.stateMu.RLock()
	defer c.stateMu.RUnlock()
	state := "stopped"
	if c.running {
		state = "running"
	}
	stats := map[string]any{}
	stats["events_emitted"] = atomic.LoadUint64(&c.eventsEmitted)
	stats["events_filtered"] = atomic.LoadUint64(&c.eventsFiltered)
	stats["events_errored"] = atomic.LoadUint64(&c.eventsErrored)
	stats["events_lost"] = atomic.LoadUint64(&c.eventsLost)
	stats["latency_last_ms"] = float64(atomic.LoadUint64(&c.latencyLastMicros)) / 1000.0
	stats["latency_max_ms"] = float64(atomic.LoadUint64(&c.latencyMaxMicros)) / 1000.0
	if len(c.probeSet) > 0 {
		var names []string
		for _, p := range c.probeSet {
			names = append(names, fmt.Sprintf("%s/%s", p.TraceGroup, p.TracePoint))
		}
		stats["attached_probes"] = names
	}
	if c.env.KernelVersion != "" {
		stats["kernel_version"] = c.env.KernelVersion
	}
	if c.env.TraceFSPath != "" {
		stats["tracefs"] = c.env.TraceFSPath
	}
	if c.buildInfo.SourceHash != "" {
		stats["object_hash"] = c.buildInfo.SourceHash
	}
	if c.buildInfo.Target != "" {
		stats["target"] = c.buildInfo.Target
	}
	if c.buildInfo.Clang != "" {
		stats["clang"] = c.buildInfo.Clang
	}
	if perfStats, err := c.snapshotPerfStatsLocked(); err == nil {
		if perfStats.Emitted > 0 {
			stats["perf_events_emitted"] = perfStats.Emitted
		}
		if perfStats.Errors > 0 {
			stats["perf_events_errors"] = perfStats.Errors
		}
		if perfStats.Dropped > 0 {
			stats["perf_queue_dropped"] = perfStats.Dropped
		}
		if perfStats.LastError != 0 {
			stats["perf_last_errno"] = perfStats.LastError
		}
	} else {
		stats["perf_stats_error"] = err.Error()
	}
	return CollectorStatus{
		Name:      c.Name(),
		Kind:      KindEBPF,
		State:     state,
		StartedAt: c.startedAt,
		LastError: c.lastError,
		Stats:     stats,
	}
}

func (c *ebpfCollector) setLastError(err error) {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	if err == nil {
		c.lastError = ""
		return
	}
	c.lastError = err.Error()
}

func (c *ebpfCollector) snapshotPerfStatsLocked() (perfEventStats, error) {
	var total perfEventStats
	if c.objects == nil || c.objects.EventStats == nil {
		return total, nil
	}
	key := uint32(0)
	var perCPU []perfEventStats
	if err := c.objects.EventStats.Lookup(&key, &perCPU); err != nil {
		return total, err
	}
	for _, entry := range perCPU {
		total.Emitted += entry.Emitted
		total.Errors += entry.Errors
		total.Dropped += entry.Dropped
		if entry.LastError != 0 {
			total.LastError = entry.LastError
		}
	}
	return total, nil
}

func (c *ebpfCollector) consumePerfEvents(ctx context.Context, handler EventHandler, reader *perf.Reader) {
	defer c.readWG.Done()
	if reader == nil {
		return
	}
	maxBatch := c.cfg.Sampling.MaxEventsPerBatch
	batchCount := 0
	for {
		record, err := reader.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) || errors.Is(err, io.EOF) || ctx.Err() != nil {
				return
			}
			c.setLastError(fmt.Errorf("perf read: %w", err))
			atomic.AddUint64(&c.eventsErrored, 1)
			continue
		}
		if record.LostSamples > 0 {
			atomic.AddUint64(&c.eventsLost, uint64(record.LostSamples))
			continue
		}
		event, kernelTS, err := convertEBPFEvent(record.RawSample, c.Name(), c.cfg.Name)
		if err != nil {
			c.setLastError(err)
			atomic.AddUint64(&c.eventsErrored, 1)
			continue
		}
		if !c.matchesFilters(event) {
			atomic.AddUint64(&c.eventsFiltered, 1)
			continue
		}
		if c.sampler != nil && !c.sampler.allow(time.Now()) {
			atomic.AddUint64(&c.eventsFiltered, 1)
			continue
		}
		c.updateLatencyFromKernel(kernelTS)
		if handler != nil {
			if err := handler.HandleEvent(context.Background(), event); err != nil {
				atomic.AddUint64(&c.eventsErrored, 1)
				c.setLastError(err)
				continue
			}
		}
		atomic.AddUint64(&c.eventsEmitted, 1)
		batchCount++
		if maxBatch > 0 && batchCount >= maxBatch {
			batchCount = 0
			runtime.Gosched()
		}
	}
}

func (c *ebpfCollector) matchesFilters(event *SystemEvent) bool {
	if len(c.cfg.Filters.Include) > 0 {
		if !filterMatchesAll(c.cfg.Filters.Include, event) {
			return false
		}
	}
	if len(c.cfg.Filters.Exclude) > 0 {
		if filterMatchesAny(c.cfg.Filters.Exclude, event) {
			return false
		}
	}
	return true
}

func convertEBPFEvent(sample []byte, sourceName, collectorName string) (*SystemEvent, uint64, error) {
	expectedSize := binary.Size(syscallEvent{})
	if len(sample) < expectedSize {
		return nil, 0, fmt.Errorf("ebpf sample too small: got %d bytes", len(sample))
	}
	var evt syscallEvent
	reader := bytes.NewReader(sample)
	if err := binary.Read(reader, binary.LittleEndian, &evt); err != nil {
		return nil, 0, fmt.Errorf("decode ebpf event: %w", err)
	}
	payload := map[string]any{
		"pid":                 evt.PID,
		"tgid":                evt.TGID,
		"comm":                trimCString(evt.Comm[:]),
		"aux":                 evt.Aux,
		"event_code":          evt.EventType,
		"kernel_timestamp_ns": evt.Timestamp,
	}
	metadata := map[string]string{
		"backend":   "ebpf",
		"collector": collectorName,
	}
	return &SystemEvent{
		Timestamp: time.Now(),
		EventType: ebpfEventTypeName(evt.EventType),
		Source:    sourceName,
		Payload:   payload,
		Metadata:  metadata,
	}, evt.Timestamp, nil
}

func ebpfEventTypeName(code uint32) string {
	switch code {
	case ebpfEventTypeExec:
		return "process.exec"
	case ebpfEventTypeExit:
		return "process.exit"
	default:
		return fmt.Sprintf("ebpf.%d", code)
	}
}

func trimCString(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	n := bytes.IndexByte(data, 0)
	if n < 0 {
		n = len(data)
	}
	return string(data[:n])
}

func (c *ebpfCollector) updateLatencyFromKernel(kernelTS uint64) {
	if kernelTS == 0 {
		return
	}
	now, err := monotonicNowNS()
	if err != nil || now <= kernelTS {
		return
	}
	delay := (now - kernelTS) / 1000
	atomic.StoreUint64(&c.latencyLastMicros, delay)
	for {
		prev := atomic.LoadUint64(&c.latencyMaxMicros)
		if delay <= prev {
			break
		}
		if atomic.CompareAndSwapUint64(&c.latencyMaxMicros, prev, delay) {
			break
		}
	}
}

func monotonicNowNS() (uint64, error) {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return 0, err
	}
	return uint64(ts.Sec)*1e9 + uint64(ts.Nsec), nil
}

func (c *ebpfCollector) resolveProbes() ([]ebpfProbe, error) {
	names := c.cfg.Probes
	if len(names) == 0 {
		names = append([]string(nil), defaultProbeOrder...)
	}
	seen := make(map[string]struct{}, len(names))
	var probes []ebpfProbe
	for _, name := range names {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		def, ok := availableEBPFProbes[name]
		if !ok {
			return nil, fmt.Errorf("unknown ebpf probe %q", name)
		}
		seen[name] = struct{}{}
		probes = append(probes, def)
	}
	if len(probes) == 0 {
		return nil, errors.New("no ebpf probes selected")
	}
	return probes, nil
}

func (c *ebpfCollector) attachProbes(objects *ebpfObjects, probes []ebpfProbe) ([]link.Link, error) {
	var links []link.Link
	for _, probe := range probes {
		prog, err := c.programForProbe(objects, probe.Program)
		if err != nil {
			return links, err
		}
		l, err := link.Tracepoint(probe.TraceGroup, probe.TracePoint, prog, nil)
		if err != nil {
			return links, fmt.Errorf("attach %s/%s: %w", probe.TraceGroup, probe.TracePoint, err)
		}
		links = append(links, l)
	}
	return links, nil
}

func (c *ebpfCollector) programForProbe(objects *ebpfObjects, symbol string) (*ebpf.Program, error) {
	switch symbol {
	case "handle_sys_enter_execve":
		return objects.HandleSysEnterExecve, nil
	case "handle_sched_process_exit":
		return objects.HandleSchedProcessExit, nil
	default:
		return nil, fmt.Errorf("unsupported program symbol %s", symbol)
	}
}

type envDeps struct {
	goos                string
	goarch              string
	kernelVersion       func() (string, int, int, int, error)
	detectTraceFS       func() (string, error)
	stat                func(string) (os.FileInfo, error)
	lookPath            func(string) (string, error)
	geteuid             func() int
	readUnprivilegedBPF func() (bool, error)
}

func (d envDeps) withDefaults() envDeps {
	if d.goos == "" {
		d.goos = runtime.GOOS
	}
	if d.goarch == "" {
		d.goarch = runtime.GOARCH
	}
	if d.kernelVersion == nil {
		d.kernelVersion = kernelVersion
	}
	if d.detectTraceFS == nil {
		d.detectTraceFS = detectTraceFS
	}
	if d.stat == nil {
		d.stat = os.Stat
	}
	if d.lookPath == nil {
		d.lookPath = exec.LookPath
	}
	if d.geteuid == nil {
		d.geteuid = os.Geteuid
	}
	if d.readUnprivilegedBPF == nil {
		d.readUnprivilegedBPF = readUnprivilegedBPF
	}
	return d
}

func inspectEBPFEnvironment(settings map[string]any) (ebpfEnvironment, error) {
	return inspectEBPFEnvironmentWithDeps(settings, envDeps{})
}

func inspectEBPFEnvironmentWithDeps(settings map[string]any, deps envDeps) (ebpfEnvironment, error) {
	deps = deps.withDefaults()
	var env ebpfEnvironment
	if deps.goos != "linux" {
		return env, errors.New("ebpf collectors require Linux")
	}
	version, maj, min, patch, err := deps.kernelVersion()
	if err != nil {
		return env, err
	}
	if maj < minKernelMajor || (maj == minKernelMajor && min < minKernelMinor) {
		return env, fmt.Errorf("kernel %s is too old, require >= %d.%d", version, minKernelMajor, minKernelMinor)
	}
	tracefs := strings.TrimSpace(stringSetting(settings, "tracefs_path"))
	if tracefs == "" {
		tracefs, err = deps.detectTraceFS()
		if err != nil {
			return env, err
		}
	} else {
		if stat, statErr := deps.stat(tracefs); statErr != nil || !stat.IsDir() {
			if statErr == nil {
				statErr = fmt.Errorf("not a directory")
			}
			return env, fmt.Errorf("tracefs path %s invalid: %w", tracefs, statErr)
		}
	}
	btfPath := strings.TrimSpace(stringSetting(settings, "btf_path"))
	if btfPath == "" {
		btfPath = "/sys/kernel/btf/vmlinux"
	}
	if stat, statErr := deps.stat(btfPath); statErr != nil || stat.IsDir() {
		if statErr == nil {
			statErr = fmt.Errorf("is a directory")
		}
		return env, fmt.Errorf("kernel BTF file %s not accessible: %w", btfPath, statErr)
	}
	clangPath := stringSetting(settings, "clang_path")
	if clangPath == "" {
		clangPath = "clang"
	}
	if _, err := deps.lookPath(clangPath); err != nil {
		return env, fmt.Errorf("clang not found (looked for %s): %w", clangPath, err)
	}
	if deps.geteuid() != 0 {
		disabled, err := deps.readUnprivilegedBPF()
		if err != nil {
			return env, fmt.Errorf("read unprivileged_bpf_disabled: %w", err)
		}
		if disabled {
			return env, errors.New("ebpf collectors require root or CAP_BPF privileges")
		}
	}
	env = ebpfEnvironment{
		KernelVersion: version,
		KernelMajor:   maj,
		KernelMinor:   min,
		KernelPatch:   patch,
		TraceFSPath:   tracefs,
		BTFPath:       btfPath,
		ClangPath:     clangPath,
		Target:        bpfTargetFromArch(deps.goarch),
		ArchMacro:     bpfArchMacro(deps.goarch),
	}
	return env, nil
}

func compileEmbeddedProgram(ctx context.Context, env ebpfEnvironment, settings map[string]any) ([]byte, compileMetadata, error) {
	source := ebpfSyscallProgramSource
	if strings.TrimSpace(source) == "" {
		return nil, compileMetadata{}, errors.New("embedded ebpf program source missing")
	}
	tmpDir, err := os.MkdirTemp("", "d-eyes-ebpf-*")
	if err != nil {
		return nil, compileMetadata{}, fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	srcPath := filepath.Join(tmpDir, "collector.bpf.c")
	if err := os.WriteFile(srcPath, []byte(source), 0o644); err != nil {
		return nil, compileMetadata{}, fmt.Errorf("write ebpf source: %w", err)
	}
	objPath := filepath.Join(tmpDir, "collector.bpf.o")
	args := []string{
		"-O2",
		"-g",
		"-std=gnu99",
		"-Wall",
		"-Werror",
		"-fno-stack-protector",
		"-fno-builtin",
		"-fno-asynchronous-unwind-tables",
		"-target", env.Target,
		"-D__TARGET_ARCH_" + env.ArchMacro,
		"-D__BPF_TRACING__",
		"-c", srcPath,
		"-o", objPath,
	}
	args = append(args, extraClangFlags(settings)...)

	cmd := exec.CommandContext(ctx, env.ClangPath, args...)
	var stderr bytes.Buffer
	cmd.Stdout = io.Discard
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, compileMetadata{}, fmt.Errorf("clang compile failed: %w\n%s", err, stderr.String())
	}
	data, err := os.ReadFile(objPath)
	if err != nil {
		return nil, compileMetadata{}, fmt.Errorf("read ebpf object: %w", err)
	}
	meta := compileMetadata{
		Clang:       env.ClangPath,
		Target:      env.Target,
		SourceHash:  hashSource(source),
		ObjectBytes: len(data),
		Flags:       args,
	}
	return data, meta, nil
}

type compileMetadata struct {
	Clang       string
	Target      string
	SourceHash  string
	ObjectBytes int
	Flags       []string
}

func kernelVersion() (string, int, int, int, error) {
	var uts unix.Utsname
	if err := unix.Uname(&uts); err != nil {
		return "", 0, 0, 0, fmt.Errorf("uname: %w", err)
	}
	release := releaseBytesToString(uts.Release[:])
	parts := strings.Split(release, ".")
	parse := func(idx int) int {
		if idx >= len(parts) {
			return 0
		}
		val, _ := strconv.Atoi(trimVersion(parts[idx]))
		return val
	}
	return release, parse(0), parse(1), parse(2), nil
}

func trimVersion(s string) string {
	for i, ch := range s {
		if (ch < '0' || ch > '9') && ch != '-' {
			return s[:i]
		}
	}
	return s
}

func releaseBytesToString(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	tmp := make([]int8, len(data))
	for i, b := range data {
		tmp[i] = int8(b)
	}
	return charsToString(tmp)
}

func charsToString(chars []int8) string {
	n := bytes.IndexByte(int8SliceToBytes(chars), 0)
	if n == -1 {
		n = len(chars)
	}
	return string(int8SliceToBytes(chars)[:n])
}

func int8SliceToBytes(s []int8) []byte {
	b := make([]byte, len(s))
	for i, v := range s {
		b[i] = byte(v)
	}
	return b
}

func detectTraceFS() (string, error) {
	candidates := []string{
		"/sys/kernel/tracing",
		"/sys/kernel/debug/tracing",
	}
	for _, path := range candidates {
		if st, err := os.Stat(path); err == nil && st.IsDir() {
			return path, nil
		}
	}
	return "", errors.New("tracefs not mounted (expected /sys/kernel/{,debug/}tracing)")
}

func readUnprivilegedBPF() (bool, error) {
	data, err := os.ReadFile("/proc/sys/kernel/unprivileged_bpf_disabled")
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	val := strings.TrimSpace(string(data))
	return val == "1", nil
}

func bpfTargetFromArch(goarch string) string {
	switch goarch {
	case "ppc64", "s390x":
		return "bpfeb"
	default:
		// All supported D-Eyes targets are little-endian by default.
		return "bpfel"
	}
}

func bpfArchMacro(goarch string) string {
	switch goarch {
	case "amd64":
		return "x86"
	case "arm64":
		return "arm64"
	case "arm":
		return "arm"
	case "ppc64", "ppc64le":
		return "powerpc"
	case "s390x":
		return "s390"
	case "riscv64":
		return "riscv"
	default:
		return "x86"
	}
}

func stringSetting(settings map[string]any, key string) string {
	if len(settings) == 0 {
		return ""
	}
	value, ok := settings[key]
	if !ok {
		return ""
	}
	switch t := value.(type) {
	case string:
		return t
	case fmt.Stringer:
		return t.String()
	default:
		return ""
	}
}

func intSetting(settings map[string]any, key string) int {
	if len(settings) == 0 {
		return 0
	}
	raw, ok := settings[key]
	if !ok {
		return 0
	}
	switch v := raw.(type) {
	case int:
		return v
	case int64:
		return int(v)
	case int32:
		return int(v)
	case float64:
		return int(v)
	case float32:
		return int(v)
	case string:
		if iv, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
			return iv
		}
	}
	return 0
}

func extraClangFlags(settings map[string]any) []string {
	raw := stringSetting(settings, "clang_flags")
	if raw == "" {
		return nil
	}
	parts := strings.Fields(raw)
	return parts
}

func specLogLevel(settings map[string]any) ebpf.LogLevel {
	level := stringSetting(settings, "verifier_log")
	switch strings.ToLower(level) {
	case "all", "debug":
		return verifierLogLevelAll
	case "verbose":
		return verifierLogLevelVerbose
	default:
		return verifierLogLevelNone
	}
}

func hashSource(src string) string {
	sum := sha256.Sum256([]byte(src))
	return hex.EncodeToString(sum[:])
}

func perfBufferSize(settings map[string]any) int {
	if size := intSetting(settings, "perf_buffer_size"); size > 0 {
		return size
	}
	pages := intSetting(settings, "perf_buffer_pages")
	if pages <= 0 {
		pages = 8
	}
	return os.Getpagesize() * pages
}

func (c *ebpfCollector) logVerifierOutput(objects *ebpfObjects) {
	if objects == nil {
		return
	}
	programs := map[string]*ebpf.Program{
		"handle_sys_enter_execve":   objects.HandleSysEnterExecve,
		"handle_sched_process_exit": objects.HandleSchedProcessExit,
	}
	for name, prog := range programs {
		if prog == nil || prog.VerifierLog == "" {
			continue
		}
		fmt.Fprintf(os.Stderr, "[verifier] %s:\n%s\n", name, prog.VerifierLog)
	}
}

func (c *ebpfCollector) logVerifierError(err error) {
	var ve *ebpf.VerifierError
	if errors.As(err, &ve) {
		fmt.Fprintf(os.Stderr, "[verifier] load failed: %+v\n", ve)
	}
}
