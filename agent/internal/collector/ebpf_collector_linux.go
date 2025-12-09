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
	"net"
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
	"github.com/cilium/ebpf/perf"
	"golang.org/x/sys/unix"
)

const (
	minKernelMajor = 5
	minKernelMinor = 8

	ebpfEventTypeExec     = 1
	ebpfEventTypeExit     = 2
	ebpfEventTypeClone    = 3
	ebpfEventTypeOpen     = 10
	ebpfEventTypeWrite    = 11
	ebpfEventTypeUnlink   = 12
	ebpfEventTypeRename   = 13
	ebpfEventTypeSocket   = 20
	ebpfEventTypeConnect  = 21
	ebpfEventTypeSendmsg  = 22
	ebpfEventTypeMMap     = 30
	ebpfEventTypeMProtect = 31
	ebpfEventTypeMUnmap   = 32

	verifierLogLevelNone    ebpf.LogLevel = 0
	verifierLogLevelVerbose ebpf.LogLevel = 1
	verifierLogLevelAll     ebpf.LogLevel = 2
	ebpfDataKindNone        uint32        = iota
	ebpfDataKindString
	ebpfDataKindIPv6
	ebpfDataKindBinary
)

const (
	connectAddrTagUnix uint32 = 1
	connectAddrTagIPv6 uint32 = 2
)

type ebpfCollector struct {
	cfg             Config
	handler         EventHandler
	stateMu         sync.RWMutex
	running         bool
	startedAt       time.Time
	lastError       string
	parserManager   EBPFParserManager
	filterEngine    EventFilterEngine
	sampler         EventSampler
	detectionEngine *ebpfDetectionEngine
	detectionSink   DetectionSink

	objects    *ebpfObjects
	probeSet   []ebpfProbe
	probeMu    sync.RWMutex
	probesOK   []string
	probesFail []string
	probeLogs  []probeAttachLog
	probeMgr   *ebpfProbeManager
	probeReg   *ebpfProbeRegistry
	env        ebpfEnvironment
	cancelFunc context.CancelFunc
	buildInfo  compileMetadata
	perfReader *perf.Reader
	readWG     sync.WaitGroup

	eventsEmitted      uint64
	eventsFiltered     uint64
	eventsErrored      uint64
	eventsLost         uint64
	latencyLastMicros  uint64
	latencyMaxMicros   uint64
	compatMeta         map[string]string
	perfOpts           perf.ReaderOptions
	perfBufferBytes    int
	perfLossThreshold  uint64
	perfLossCounter    uint64
	backpressureMu     sync.Mutex
	backpressureActive bool
	backpressureReason string
	backpressureUntil  time.Time
	backpressureTarget float64
	backpressureHold   time.Duration
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
	UID       uint32
	GID       uint32
	CgroupID  uint64
	EventType uint32
	Aux       uint32
	Comm      [16]byte
	Data      [64]byte
	DataLen   uint32
	DataKind  uint32
	Extra0    uint32
	Extra1    uint32
	Extra2    uint32
	Extra3    uint32
}

// ebpfObjects hosts the maps/programs loaded from the CO-RE object.
type ebpfObjects struct {
	Events                 *ebpf.Map     `ebpf:"events"`
	EventStats             *ebpf.Map     `ebpf:"event_stats"`
	HandleSysEnterExecve   *ebpf.Program `ebpf:"handle_sys_enter_execve"`
	HandleSchedProcessExit *ebpf.Program `ebpf:"handle_sched_process_exit"`
	HandleSysEnterClone    *ebpf.Program `ebpf:"handle_sys_enter_clone"`
	HandleSysEnterOpenat   *ebpf.Program `ebpf:"handle_sys_enter_openat"`
	HandleSysEnterWrite    *ebpf.Program `ebpf:"handle_sys_enter_write"`
	HandleSysEnterUnlinkat *ebpf.Program `ebpf:"handle_sys_enter_unlinkat"`
	HandleSysEnterRenameat *ebpf.Program `ebpf:"handle_sys_enter_renameat"`
	HandleSysEnterSocket   *ebpf.Program `ebpf:"handle_sys_enter_socket"`
	HandleSysEnterConnect  *ebpf.Program `ebpf:"handle_sys_enter_connect"`
	HandleSysEnterSendmsg  *ebpf.Program `ebpf:"handle_sys_enter_sendmsg"`
	HandleSysEnterMmap     *ebpf.Program `ebpf:"handle_sys_enter_mmap"`
	HandleSysEnterMprotect *ebpf.Program `ebpf:"handle_sys_enter_mprotect"`
	HandleSysEnterMunmap   *ebpf.Program `ebpf:"handle_sys_enter_munmap"`
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
	if o.HandleSysEnterClone != nil {
		err = errors.Join(err, o.HandleSysEnterClone.Close())
		o.HandleSysEnterClone = nil
	}
	if o.HandleSysEnterOpenat != nil {
		err = errors.Join(err, o.HandleSysEnterOpenat.Close())
		o.HandleSysEnterOpenat = nil
	}
	if o.HandleSysEnterWrite != nil {
		err = errors.Join(err, o.HandleSysEnterWrite.Close())
		o.HandleSysEnterWrite = nil
	}
	if o.HandleSysEnterUnlinkat != nil {
		err = errors.Join(err, o.HandleSysEnterUnlinkat.Close())
		o.HandleSysEnterUnlinkat = nil
	}
	if o.HandleSysEnterRenameat != nil {
		err = errors.Join(err, o.HandleSysEnterRenameat.Close())
		o.HandleSysEnterRenameat = nil
	}
	if o.HandleSysEnterSocket != nil {
		err = errors.Join(err, o.HandleSysEnterSocket.Close())
		o.HandleSysEnterSocket = nil
	}
	if o.HandleSysEnterConnect != nil {
		err = errors.Join(err, o.HandleSysEnterConnect.Close())
		o.HandleSysEnterConnect = nil
	}
	if o.HandleSysEnterSendmsg != nil {
		err = errors.Join(err, o.HandleSysEnterSendmsg.Close())
		o.HandleSysEnterSendmsg = nil
	}
	if o.HandleSysEnterMmap != nil {
		err = errors.Join(err, o.HandleSysEnterMmap.Close())
		o.HandleSysEnterMmap = nil
	}
	if o.HandleSysEnterMprotect != nil {
		err = errors.Join(err, o.HandleSysEnterMprotect.Close())
		o.HandleSysEnterMprotect = nil
	}
	if o.HandleSysEnterMunmap != nil {
		err = errors.Join(err, o.HandleSysEnterMunmap.Close())
		o.HandleSysEnterMunmap = nil
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
	BTFSize       int64
	ClangPath     string
	Target        string
	ArchMacro     string
	CORESupported bool
}

type ebpfProbe struct {
	Name       string
	TraceGroup string
	TracePoint string
	Program    string
}

func newEBPFCollector(cfg Config) (EventCollector, error) {
	if runtime.GOOS != "linux" {
		return nil, fmt.Errorf("ebpf collector %q is only supported on Linux", cfg.Name)
	}
	if strings.TrimSpace(cfg.Name) == "" {
		return nil, fmt.Errorf("ebpf collector requires a non-empty name")
	}
	parserMgr := newEBPFParserManager(cfg.Parser)
	parserMgr.RegisterParser(defaultEBPFParser{})
	parserMgr.RegisterParser(execEventParser{})
	parserMgr.RegisterParser(fileEventParser{})
	parserMgr.RegisterParser(networkEventParser{})
	parserMgr.RegisterParser(memoryEventParser{})
	_ = parserMgr.UpdateConfig(cfg.Parser)
	filter := newRuleFilterEngine(cfg.Filters)
	sampler := newDynamicSampler(cfg.Sampling)
	collector := &ebpfCollector{
		cfg:                cfg,
		parserManager:      parserMgr,
		filterEngine:       filter,
		sampler:            sampler,
		probeReg:           newEBPFProbeRegistry(),
		detectionEngine:    newEBPFDetectionEngine(),
		backpressureTarget: 0.5,
		backpressureHold:   5 * time.Second,
	}
	collector.applyRuntimeSettings(cfg.Settings)
	return collector, nil
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
	manager := newEBPFProbeManager(func(symbol string) (*ebpf.Program, error) {
		return c.programForProbe(objects, symbol)
	}, defaultTracepointAttacher)
	okProbes, failProbes, attachLogs, err := manager.Apply(probes)
	if err != nil {
		cancel()
		_ = manager.Close()
		_ = objects.Close()
		c.setLastError(err)
		return err
	}
	c.updateProbeStatus(okProbes, failProbes)
	c.recordProbeLogs(attachLogs)
	perfBufSize := perfBufferSize(c.cfg.Settings)
	readerOpts := perfReaderOptions(c.cfg.Settings)
	perfReader, err := perf.NewReaderWithOptions(objects.Events, perfBufSize, readerOpts)
	if err != nil {
		cancel()
		_ = manager.Close()
		_ = objects.Close()
		c.setLastError(err)
		return fmt.Errorf("create perf reader: %w", err)
	}

	c.stateMu.Lock()
	c.handler = handler
	c.objects = objects
	c.probeSet = probes
	c.probeMgr = manager
	c.env = env
	c.buildInfo = compileMeta
	c.running = true
	c.startedAt = time.Now()
	c.lastError = ""
	c.cancelFunc = cancel
	c.perfReader = perfReader
	c.perfOpts = readerOpts
	c.perfBufferBytes = perfBufSize
	atomic.StoreUint64(&c.eventsEmitted, 0)
	atomic.StoreUint64(&c.eventsFiltered, 0)
	atomic.StoreUint64(&c.eventsErrored, 0)
	atomic.StoreUint64(&c.eventsLost, 0)
	atomic.StoreUint64(&c.latencyLastMicros, 0)
	atomic.StoreUint64(&c.latencyMaxMicros, 0)
	c.stateMu.Unlock()
	c.compatMeta = map[string]string{
		"compat.kernel.version": env.KernelVersion,
		"compat.kernel.min":     fmt.Sprintf("%d.%d", minKernelMajor, minKernelMinor),
		"compat.btf.path":       env.BTFPath,
		"compat.tracefs":        env.TraceFSPath,
		"compat.target":         env.Target,
	}
	if env.BTFSize > 0 {
		c.compatMeta["compat.btf.size_bytes"] = strconv.FormatInt(env.BTFSize, 10)
	}
	c.compatMeta["compat.core.ready"] = strconv.FormatBool(env.CORESupported)

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
	manager := c.probeMgr
	c.probeMgr = nil
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
	c.resetBackpressure()

	var multi error
	if manager != nil {
		multi = errors.Join(multi, manager.Close())
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
	if c.filterEngine != nil {
		filterStats := c.filterEngine.Stats()
		stats["filter_evaluated"] = filterStats.Evaluated
		stats["filter_dropped"] = filterStats.Dropped
	}
	if c.sampler != nil {
		samplerStats := c.sampler.Stats()
		stats["sampler_sampled"] = samplerStats.Sampled
		stats["sampler_skipped"] = samplerStats.Skipped
		stats["sampler_scale"] = samplerStats.Scale
	}
	if c.detectionEngine != nil {
		total, perRule, ids := c.detectionEngine.Stats()
		if total > 0 {
			stats["detections_total"] = total
		}
		for rule, count := range perRule {
			stats[fmt.Sprintf("detections.%s", rule)] = count
		}
		for rule, id := range ids {
			stats[fmt.Sprintf("detections.last_id.%s", rule)] = id
		}
	}
	if len(c.probeSet) > 0 {
		var names []string
		for _, p := range c.probeSet {
			names = append(names, fmt.Sprintf("%s/%s", p.TraceGroup, p.TracePoint))
		}
		stats["attached_probes"] = names
	}
	c.probeMu.RLock()
	if len(c.probesOK) > 0 {
		stats["probe_attach_success"] = append([]string(nil), c.probesOK...)
	}
	if len(c.probesFail) > 0 {
		stats["probe_attach_failure"] = append([]string(nil), c.probesFail...)
	}
	logCopy := append([]probeAttachLog(nil), c.probeLogs...)
	c.probeMu.RUnlock()
	if len(logCopy) > 0 {
		formatted := make([]map[string]string, 0, len(logCopy))
		for _, entry := range logCopy {
			record := map[string]string{
				"time":   entry.Timestamp.Format(time.RFC3339Nano),
				"probe":  entry.Probe,
				"status": entry.Status,
			}
			if entry.Detail != "" {
				record["detail"] = entry.Detail
			}
			formatted = append(formatted, record)
		}
		stats["probe_attach_log"] = formatted
	}
	if c.env.KernelVersion != "" {
		stats["kernel_version"] = c.env.KernelVersion
	}
	if c.env.TraceFSPath != "" {
		stats["tracefs"] = c.env.TraceFSPath
	}
	if c.buildInfo.SourceHash != "" {
		stats["object_hash"] = c.buildInfo.SourceHash
		if c.buildInfo.ObjectVersion != "" {
			stats["build.object_version"] = c.buildInfo.ObjectVersion
		}
	}
	if c.buildInfo.Target != "" {
		stats["target"] = c.buildInfo.Target
	}
	if c.buildInfo.Clang != "" {
		stats["clang"] = c.buildInfo.Clang
	}
	if c.buildInfo.ObjectBytes > 0 {
		stats["build.object_bytes"] = c.buildInfo.ObjectBytes
	}
	if len(c.buildInfo.Flags) > 0 {
		stats["build.flags"] = strings.Join(c.buildInfo.Flags, " ")
	}
	if c.buildInfo.BuildLog != "" {
		stats["build.compile_log"] = c.buildInfo.BuildLog
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
	if c.perfBufferBytes > 0 {
		stats["perf_buffer_bytes"] = c.perfBufferBytes
	}
	if c.perfOpts.Watermark > 0 {
		stats["perf_watermark_bytes"] = c.perfOpts.Watermark
	}
	if c.perfOpts.WakeupEvents > 0 {
		stats["perf_wakeup_events"] = c.perfOpts.WakeupEvents
	}
	if c.perfOpts.Overwritable {
		stats["perf_overwritable"] = true
	}
	stats["perf_loss_threshold"] = c.perfLossThreshold
	c.backpressureMu.Lock()
	stats["backpressure_active"] = c.backpressureActive
	if c.backpressureReason != "" {
		stats["backpressure_reason"] = c.backpressureReason
	}
	if c.backpressureActive && !c.backpressureUntil.IsZero() {
		stats["backpressure_until"] = c.backpressureUntil.Format(time.RFC3339Nano)
	}
	c.backpressureMu.Unlock()
	meta := map[string]string{}
	for k, v := range c.compatMeta {
		meta[k] = v
	}
	return CollectorStatus{
		Name:      c.Name(),
		Kind:      KindEBPF,
		State:     state,
		StartedAt: c.startedAt,
		LastError: c.lastError,
		Stats:     stats,
		Metadata:  meta,
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
		c.maybeRecoverBackpressure()
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
			c.onPerfLoss(uint64(record.LostSamples))
			continue
		}
		event, kernelTS, err := c.parseEBPFEvent(record.RawSample)
		if err != nil {
			c.setLastError(err)
			atomic.AddUint64(&c.eventsErrored, 1)
			continue
		}
		if c.filterEngine != nil && !c.filterEngine.ShouldProcess(event) {
			atomic.AddUint64(&c.eventsFiltered, 1)
			continue
		}
		if c.sampler != nil && !c.sampler.ShouldSample(event.EventType, event.Metadata) {
			atomic.AddUint64(&c.eventsFiltered, 1)
			continue
		}
		if detection := c.detectEvent(event); detection != nil {
			c.handleDetection(event, detection)
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

func (c *ebpfCollector) detectEvent(event *SystemEvent) *DetectionResult {
	if c.detectionEngine == nil || event == nil {
		return nil
	}
	return c.detectionEngine.Evaluate(event)
}

func (c *ebpfCollector) handleDetection(event *SystemEvent, result *DetectionResult) {
	if event == nil || result == nil {
		return
	}
	if event.Metadata == nil {
		event.Metadata = make(map[string]string, 4)
	}
	event.Metadata["detection.rule"] = result.RuleID
	event.Metadata["detection.name"] = result.Name
	event.Metadata["detection.severity"] = result.Severity
	event.Metadata["detection.action"] = string(result.Action)
	if result.Description != "" {
		event.Metadata["detection.description"] = result.Description
	}
	if event.Tags == nil {
		event.Tags = make(map[string]string, 1)
	}
	event.Tags["detection"] = "true"
	if c.detectionSink != nil {
		resCopy := *result
		go c.detectionSink.OnDetection(context.Background(), cloneSystemEvent(event), resCopy)
	}
}

func (c *ebpfCollector) parseEBPFEvent(sample []byte) (*SystemEvent, uint64, error) {
	if c.parserManager != nil {
		return c.parserManager.Parse(sample, c.Name(), c.cfg.Name)
	}
	return convertEBPFEvent(sample, c.Name(), c.cfg.Name)
}

func convertEBPFEvent(sample []byte, sourceName, collectorName string) (*SystemEvent, uint64, error) {
	evt, err := decodeSyscallEvent(sample)
	if err != nil {
		return nil, 0, err
	}
	event := buildEBPFSystemEvent(evt, sourceName, collectorName)
	return event, evt.Timestamp, nil
}

func ebpfEventTypeName(code uint32) string {
	switch code {
	case ebpfEventTypeExec:
		return "process.exec"
	case ebpfEventTypeExit:
		return "process.exit"
	case ebpfEventTypeClone:
		return "process.clone"
	case ebpfEventTypeOpen:
		return "fs.open"
	case ebpfEventTypeWrite:
		return "fs.write"
	case ebpfEventTypeUnlink:
		return "fs.unlink"
	case ebpfEventTypeRename:
		return "fs.rename"
	case ebpfEventTypeSocket:
		return "net.socket"
	case ebpfEventTypeConnect:
		return "net.connect"
	case ebpfEventTypeSendmsg:
		return "net.sendmsg"
	case ebpfEventTypeMMap:
		return "mem.mmap"
	case ebpfEventTypeMProtect:
		return "mem.mprotect"
	case ebpfEventTypeMUnmap:
		return "mem.munmap"
	default:
		return fmt.Sprintf("ebpf.%d", code)
	}
}

func familyName(code uint32) string {
	switch code {
	case unix.AF_INET:
		return "AF_INET"
	case unix.AF_INET6:
		return "AF_INET6"
	case unix.AF_UNIX:
		return "AF_UNIX"
	default:
		return fmt.Sprintf("%d", code)
	}
}

func formatIPv4(addr uint32) string {
	if addr == 0 {
		return ""
	}
	var bytes [4]byte
	binary.BigEndian.PutUint32(bytes[:], addr)
	return fmt.Sprintf("%d.%d.%d.%d", bytes[0], bytes[1], bytes[2], bytes[3])
}

func formatIPv6(data []byte, length uint32) string {
	if len(data) == 0 || length == 0 {
		return ""
	}
	if length > uint32(len(data)) {
		length = uint32(len(data))
	}
	if length < net.IPv6len {
		return ""
	}
	ip := make(net.IP, net.IPv6len)
	copy(ip, data[:net.IPv6len])
	return ip.String()
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
	reg := c.probeReg
	if reg == nil {
		reg = newEBPFProbeRegistry()
		c.probeReg = reg
	}
	names := c.cfg.Probes
	if len(names) == 0 {
		names = reg.DefaultNames()
	}
	return reg.Resolve(names)
}

func (c *ebpfCollector) reloadProbes() error {
	c.stateMu.RLock()
	manager := c.probeMgr
	running := c.running
	c.stateMu.RUnlock()
	if !running || manager == nil {
		return nil
	}
	probes, err := c.resolveProbes()
	if err != nil {
		return err
	}
	ok, fail, logs, err := manager.Apply(probes)
	c.updateProbeStatus(ok, fail)
	c.recordProbeLogs(logs)
	if err != nil {
		return err
	}
	c.stateMu.Lock()
	c.probeSet = probes
	c.stateMu.Unlock()
	return nil
}

func (c *ebpfCollector) UpdateConfig(cfg Config) {
	c.stateMu.Lock()
	c.cfg = cfg
	c.stateMu.Unlock()
	c.applyConfig(cfg)
	if err := c.reloadProbes(); err != nil {
		c.setLastError(err)
	}
}

func (c *ebpfCollector) applyConfig(cfg Config) {
	c.applyRuntimeSettings(cfg.Settings)
	if c.parserManager != nil {
		_ = c.parserManager.UpdateConfig(cfg.Parser)
	}
	if c.filterEngine != nil {
		_ = c.filterEngine.UpdateConfig(cfg.Filters)
	}
	if c.sampler != nil {
		_ = c.sampler.UpdateConfig(cfg.Sampling)
	}
}

func (c *ebpfCollector) applyRuntimeSettings(settings map[string]any) {
	scale := floatSetting(settings, "backpressure_scale")
	if scale <= 0 || scale > 1 {
		scale = 0.5
	}
	holdMS := intSetting(settings, "backpressure_hold_ms")
	if holdMS <= 0 {
		holdMS = 5000
	}
	threshold := intSetting(settings, "perf_loss_threshold")
	c.backpressureMu.Lock()
	c.backpressureTarget = scale
	c.backpressureHold = time.Duration(holdMS) * time.Millisecond
	if threshold <= 0 {
		c.perfLossThreshold = 0
		c.perfLossCounter = 0
	} else {
		c.perfLossThreshold = uint64(threshold)
	}
	c.backpressureMu.Unlock()
}

func (c *ebpfCollector) updateProbeStatus(ok, failed []string) {
	c.probeMu.Lock()
	c.probesOK = append([]string(nil), ok...)
	c.probesFail = append([]string(nil), failed...)
	c.probeMu.Unlock()
}

const maxProbeLogs = 10

func (c *ebpfCollector) recordProbeLogs(logs []probeAttachLog) {
	if len(logs) == 0 {
		return
	}
	c.probeMu.Lock()
	c.probeLogs = append(c.probeLogs, logs...)
	if excess := len(c.probeLogs) - maxProbeLogs; excess > 0 {
		c.probeLogs = append([]probeAttachLog(nil), c.probeLogs[excess:]...)
	}
	c.probeMu.Unlock()
}

func (c *ebpfCollector) onPerfLoss(loss uint64) {
	if loss == 0 {
		return
	}
	threshold := atomic.LoadUint64(&c.perfLossThreshold)
	if threshold == 0 {
		return
	}
	total := atomic.AddUint64(&c.perfLossCounter, loss)
	if total < threshold {
		return
	}
	atomic.StoreUint64(&c.perfLossCounter, 0)
	c.activateBackpressure(fmt.Sprintf("lost %d samples", loss))
}

func (c *ebpfCollector) activateBackpressure(reason string) {
	c.backpressureMu.Lock()
	defer c.backpressureMu.Unlock()
	c.backpressureActive = true
	c.backpressureReason = reason
	hold := c.backpressureHold
	if hold <= 0 {
		hold = 5 * time.Second
	}
	c.backpressureUntil = time.Now().Add(hold)
	target := c.backpressureTarget
	if target <= 0 || target > 1 {
		target = 1.0
	}
	if sampler, ok := c.sampler.(*dynamicSampler); ok {
		sampler.SetAdaptiveScale(target)
	}
}

func (c *ebpfCollector) maybeRecoverBackpressure() {
	c.backpressureMu.Lock()
	defer c.backpressureMu.Unlock()
	if !c.backpressureActive {
		return
	}
	if time.Now().Before(c.backpressureUntil) {
		return
	}
	c.clearBackpressureLocked()
}

func (c *ebpfCollector) clearBackpressureLocked() {
	if !c.backpressureActive {
		return
	}
	c.backpressureActive = false
	c.backpressureReason = ""
	c.backpressureUntil = time.Time{}
	if sampler, ok := c.sampler.(*dynamicSampler); ok {
		sampler.SetAdaptiveScale(1.0)
	}
}

func (c *ebpfCollector) resetBackpressure() {
	c.backpressureMu.Lock()
	defer c.backpressureMu.Unlock()
	c.clearBackpressureLocked()
}

func (c *ebpfCollector) programForProbe(objects *ebpfObjects, symbol string) (*ebpf.Program, error) {
	switch symbol {
	case "handle_sys_enter_execve":
		return objects.HandleSysEnterExecve, nil
	case "handle_sched_process_exit":
		return objects.HandleSchedProcessExit, nil
	case "handle_sys_enter_clone":
		return objects.HandleSysEnterClone, nil
	case "handle_sys_enter_openat":
		return objects.HandleSysEnterOpenat, nil
	case "handle_sys_enter_write":
		return objects.HandleSysEnterWrite, nil
	case "handle_sys_enter_unlinkat":
		return objects.HandleSysEnterUnlinkat, nil
	case "handle_sys_enter_renameat":
		return objects.HandleSysEnterRenameat, nil
	case "handle_sys_enter_socket":
		return objects.HandleSysEnterSocket, nil
	case "handle_sys_enter_connect":
		return objects.HandleSysEnterConnect, nil
	case "handle_sys_enter_sendmsg":
		return objects.HandleSysEnterSendmsg, nil
	case "handle_sys_enter_mmap":
		return objects.HandleSysEnterMmap, nil
	case "handle_sys_enter_mprotect":
		return objects.HandleSysEnterMprotect, nil
	case "handle_sys_enter_munmap":
		return objects.HandleSysEnterMunmap, nil
	default:
		return nil, fmt.Errorf("unsupported program symbol %s", symbol)
	}
}

func (c *ebpfCollector) SetDetectionSink(sink DetectionSink) {
	c.stateMu.Lock()
	c.detectionSink = sink
	c.stateMu.Unlock()
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
	statInfo, statErr := deps.stat(btfPath)
	if statErr != nil || statInfo.IsDir() {
		if statErr == nil {
			statErr = fmt.Errorf("is a directory")
		}
		return env, fmt.Errorf("kernel BTF file %s not accessible: %w", btfPath, statErr)
	}
	btfSize := statInfo.Size()
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
		BTFSize:       btfSize,
		ClangPath:     clangPath,
		Target:        bpfTargetFromArch(deps.goarch),
		ArchMacro:     bpfArchMacro(deps.goarch),
		CORESupported: btfSize > 0,
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
	buildLog := strings.TrimSpace(stderr.String())
	sourceHash := hashSource(source)
	meta := compileMetadata{
		Clang:         env.ClangPath,
		Target:        env.Target,
		SourceHash:    sourceHash,
		ObjectBytes:   len(data),
		Flags:         args,
		BuildLog:      buildLog,
		ObjectVersion: fmt.Sprintf("%s:%d", sourceHash, len(data)),
	}
	return data, meta, nil
}

type compileMetadata struct {
	Clang         string
	Target        string
	SourceHash    string
	ObjectBytes   int
	Flags         []string
	BuildLog      string
	ObjectVersion string
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

func floatSetting(settings map[string]any, key string) float64 {
	if len(settings) == 0 {
		return 0
	}
	raw, ok := settings[key]
	if !ok {
		return 0
	}
	switch v := raw.(type) {
	case float64:
		return v
	case float32:
		return float64(v)
	case int:
		return float64(v)
	case int64:
		return float64(v)
	case string:
		if f, err := strconv.ParseFloat(strings.TrimSpace(v), 64); err == nil {
			return f
		}
	}
	return 0
}

func boolSetting(settings map[string]any, key string) bool {
	if len(settings) == 0 {
		return false
	}
	raw, ok := settings[key]
	if !ok {
		return false
	}
	switch v := raw.(type) {
	case bool:
		return v
	case string:
		lower := strings.ToLower(strings.TrimSpace(v))
		return lower == "1" || lower == "true" || lower == "yes" || lower == "on"
	case int:
		return v != 0
	case int64:
		return v != 0
	}
	return false
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

func perfReaderOptions(settings map[string]any) perf.ReaderOptions {
	opts := perf.ReaderOptions{}
	if watermark := intSetting(settings, "perf_watermark_bytes"); watermark > 0 {
		opts.Watermark = watermark
	} else if wake := intSetting(settings, "perf_wakeup_events"); wake > 0 {
		opts.WakeupEvents = wake
	}
	if boolSetting(settings, "perf_overwritable") {
		opts.Overwritable = true
	}
	return opts
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
