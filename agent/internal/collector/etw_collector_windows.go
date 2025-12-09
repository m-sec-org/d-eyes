//go:build windows

package collector

import (
	"context"
	"encoding/hex"
	"fmt"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	eventTraceRealTimeMode      = 0x00000100
	eventTraceControlStop       = 1
	wnodeFlagTracedGUID         = 0x00020000
	eventControlEnable          = 1
	maxSessionNameLength        = 128
	defaultCollectorLogName     = "d-eyes-etw"
	enableParametersVersion1    = 1
	errorWmiInstanceNotFound    = 4201
	tracePropertiesBufferSize   = uint32(unsafe.Sizeof(eventTraceProperties{}))
	processTraceModeRealtime    = 0x00000100
	processTraceModeEventRecord = 0x10000000
	invalidProcessTraceHandle   = ^uintptr(0)
	defaultETWQueueSize         = 4096
)

var (
	modAdvapi32        = windows.NewLazySystemDLL("advapi32.dll")
	procStartTraceW    = modAdvapi32.NewProc("StartTraceW")
	procControlTraceW  = modAdvapi32.NewProc("ControlTraceW")
	procEnableTraceEx2 = modAdvapi32.NewProc("EnableTraceEx2")
	procOpenTraceW     = modAdvapi32.NewProc("OpenTraceW")
	procProcessTrace   = modAdvapi32.NewProc("ProcessTrace")
	procCloseTrace     = modAdvapi32.NewProc("CloseTrace")
)

type etwCollector struct {
	cfg               Config
	sessionHandle     windows.Handle
	name              string
	handler           EventHandler
	startedAt         time.Time
	lastError         string
	stateMu           sync.RWMutex
	running           bool
	traceHandle       windows.Handle
	traceLogfile      *eventTraceLogfile
	eventsEmitted     uint64
	eventsFiltered    uint64
	eventsErrored     uint64
	queueDropped      uint64
	latencyLastMicros uint64
	latencyMaxMicros  uint64

	parserManager ETWParserManager
	filterEngine  EventFilterEngine
	sampler       EventSampler

	pluginLoader      *etwPluginLoader
	eventProcessors   []EventProcessor
	processorStats    processorStats
	detectionEngine   *detectionEngine
	detectionSink     DetectionSink
	activePluginNames map[string]struct{}

	eventQueue     chan *etwEventEnvelope
	eventQueueSize int
	workerCount    int
	workerCtx      context.Context
	workerCancel   context.CancelFunc
	workerWG       sync.WaitGroup
	eventPool      sync.Pool
	monitor        ETWMonitor
}

func newETWCollector(cfg Config) (EventCollector, error) {
	name := cfg.Name
	if strings.TrimSpace(name) == "" {
		name = defaultCollectorLogName
	}
	if len(name) > maxSessionNameLength {
		name = name[:maxSessionNameLength]
	}
	workerCount := determineETWWorkerCount(cfg.Settings)
	queueSize := determineETWQueueSize(cfg.Settings)
	pm := newDefaultParserManager(cfg.Parser)
	pm.RegisterParser(defaultETWParser{})
	pm.RegisterParser(securityEventParser{})
	pm.RegisterParser(systemEventParser{})
	pm.RegisterParser(applicationEventParser{})
	pm.RegisterParser(defenderEventParser{})
	pm.RegisterParser(containerEventParser{})
	_ = pm.UpdateConfig(cfg.Parser)
	loader := newETWPluginLoader()
	pluginParsers, processors, pluginNames, err := loader.Load(cfg.Parser.Plugins)
	if err != nil {
		return nil, err
	}
	for _, parser := range pluginParsers {
		pm.RegisterParser(parser)
	}
	nameSet := make(map[string]struct{}, len(pluginNames))
	for _, pluginName := range pluginNames {
		nameSet[pluginName] = struct{}{}
	}
	filter := newRuleFilterEngine(cfg.Filters)
	sampler := newDynamicSampler(cfg.Sampling)
	monitor := newDefaultETWMonitor()
	monitor.SetWorkerTotal(workerCount)
	pool := sync.Pool{
		New: func() any {
			return &etwEventEnvelope{}
		},
	}
	return &etwCollector{
		cfg:               cfg,
		name:              name,
		parserManager:     pm,
		filterEngine:      filter,
		sampler:           sampler,
		detectionEngine:   newDetectionEngine(),
		pluginLoader:      loader,
		eventProcessors:   processors,
		activePluginNames: nameSet,
		eventQueue:        make(chan *etwEventEnvelope, queueSize),
		eventQueueSize:    queueSize,
		workerCount:       workerCount,
		eventPool:         pool,
		monitor:           monitor,
	}, nil
}

func (c *etwCollector) Name() string {
	return fmt.Sprintf("etw-%s", c.name)
}

func (c *etwCollector) Start(ctx context.Context, handler EventHandler) error {
	if handler == nil {
		handler = EventHandlerFunc(func(context.Context, *SystemEvent) error { return nil })
	}
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	if c.running {
		return nil
	}
	c.startWorkerPoolLocked()
	handle, err := startTraceSession(c.name)
	if err != nil {
		c.lastError = err.Error()
		c.stopWorkerPool()
		return err
	}
	if err := c.enableProviders(handle, c.cfg.Providers); err != nil {
		c.lastError = err.Error()
		_ = stopTraceSession(handle, c.name)
		c.stopWorkerPool()
		return err
	}

	c.sessionHandle = handle
	c.running = true
	c.startedAt = time.Now()
	c.handler = handler

	go c.processTraceLoop(ctx)

	go func() {
		<-ctx.Done()
		_ = c.Stop(context.Background())
	}()
	return nil
}

func (c *etwCollector) Stop(context.Context) error {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	if !c.running {
		return nil
	}
	if c.traceHandle != 0 {
		_ = closeTrace(c.traceHandle)
		c.traceHandle = 0
	}
	c.traceLogfile = nil
	if err := stopTraceSession(c.sessionHandle, c.name); err != nil && !isIgnorableControlError(err) {
		c.lastError = err.Error()
		return err
	}
	c.sessionHandle = 0
	c.running = false
	if c.pluginLoader != nil {
		c.pluginLoader.teardown()
	}
	return nil
}

func (c *etwCollector) Status() CollectorStatus {
	c.stateMu.RLock()
	defer c.stateMu.RUnlock()
	state := "stopped"
	if c.running {
		state = "running"
	}
	stats := map[string]any{
		"events_emitted":  atomic.LoadUint64(&c.eventsEmitted),
		"events_filtered": atomic.LoadUint64(&c.eventsFiltered),
		"events_errored":  atomic.LoadUint64(&c.eventsErrored),
		"latency_last_ms": float64(atomic.LoadUint64(&c.latencyLastMicros)) / 1000.0,
		"latency_max_ms":  float64(atomic.LoadUint64(&c.latencyMaxMicros)) / 1000.0,
	}
	stats["events_queue_dropped"] = atomic.LoadUint64(&c.queueDropped)
	if c.eventQueueSize > 0 {
		stats["event_queue_capacity"] = c.eventQueueSize
	}
	stats["event_workers_total"] = c.workerCount
	if c.filterEngine != nil {
		filterStats := c.filterEngine.Stats()
		stats["filter_evaluated"] = filterStats.Evaluated
		stats["filter_dropped"] = filterStats.Dropped
	}
	if c.sampler != nil {
		samplerStats := c.sampler.Stats()
		stats["sampler_sampled"] = samplerStats.Sampled
		stats["sampler_skipped"] = samplerStats.Skipped
	}
	if c.monitor != nil {
		metrics := c.monitor.GetMetrics()
		stats["event_queue_depth"] = metrics.QueueDepth
		stats["event_workers_busy"] = metrics.WorkersBusy
		stats["event_latency_avg_ms"] = metrics.EventLatencyAvg.Milliseconds()
		stats["event_latency_peak_ms"] = metrics.EventLatencyMax.Milliseconds()
		stats["collector_cpu_usage"] = metrics.CPUUsage
		stats["collector_memory_bytes"] = metrics.MemoryUsage
		stats["collector_events_dropped"] = metrics.EventsDropped
	}
	if c.detectionEngine != nil {
		total, perRule, ids := c.detectionEngine.Stats()
		stats["detections_total"] = total
		for rule, count := range perRule {
			stats[fmt.Sprintf("detections.%s", rule)] = count
		}
		for rule, id := range ids {
			stats[fmt.Sprintf("detections.last_id.%s", rule)] = id
		}
	}
	if procStats := c.processorStats.Snapshot("processors"); len(procStats) > 0 {
		for k, v := range procStats {
			stats[k] = v
		}
	}
	return CollectorStatus{
		Name:      c.Name(),
		Kind:      KindETW,
		State:     state,
		StartedAt: c.startedAt,
		LastError: c.lastError,
		Stats:     stats,
	}
}

func (c *etwCollector) enableProviders(handle windows.Handle, providers []string) error {
	for _, provider := range providers {
		guid, err := windows.GUIDFromString(provider)
		if err != nil {
			return fmt.Errorf("invalid provider GUID %q: %w", provider, err)
		}
		if err := enableTraceProvider(handle, &guid); err != nil {
			return fmt.Errorf("enable provider %s: %w", provider, err)
		}
	}
	return nil
}

func startTraceSession(name string) (windows.Handle, error) {
	namePtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return 0, err
	}
	props := newEventTraceProperties()
	props.Wnode.BufferSize = tracePropertiesBufferSize
	props.Wnode.Flags = wnodeFlagTracedGUID
	props.LogFileMode = eventTraceRealTimeMode

	var handle windows.Handle
	r1, _, e1 := procStartTraceW.Call(
		uintptr(unsafe.Pointer(&handle)),
		uintptr(unsafe.Pointer(namePtr)),
		uintptr(unsafe.Pointer(props)),
	)
	if r1 != windows.ERROR_SUCCESS {
		if e1 != windows.ERROR_SUCCESS {
			return 0, e1
		}
		return 0, windows.Errno(r1)
	}
	return handle, nil
}

func stopTraceSession(handle windows.Handle, name string) error {
	namePtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	props := newEventTraceProperties()
	props.Wnode.BufferSize = tracePropertiesBufferSize
	props.Wnode.Flags = wnodeFlagTracedGUID

	r1, _, e1 := procControlTraceW.Call(
		uintptr(handle),
		uintptr(unsafe.Pointer(namePtr)),
		uintptr(unsafe.Pointer(props)),
		uintptr(eventTraceControlStop),
	)
	if r1 != windows.ERROR_SUCCESS {
		if e1 != windows.ERROR_SUCCESS {
			return e1
		}
		return windows.Errno(r1)
	}
	return nil
}

func enableTraceProvider(handle windows.Handle, provider *windows.GUID) error {
	params := enableTraceParameters{
		Version: enableParametersVersion1,
	}
	r1, _, e1 := procEnableTraceEx2.Call(
		uintptr(handle),
		uintptr(unsafe.Pointer(provider)),
		uintptr(eventControlEnable),
		uintptr(0xff),
		uintptr(0),
		uintptr(0),
		uintptr(0),
		uintptr(unsafe.Pointer(&params)),
	)
	if r1 != windows.ERROR_SUCCESS {
		if e1 != windows.ERROR_SUCCESS {
			return e1
		}
		return windows.Errno(r1)
	}
	return nil
}

func (c *etwCollector) startWorkerPoolLocked() {
	if c.workerCtx != nil {
		return
	}
	if c.workerCount <= 0 {
		c.workerCount = determineETWWorkerCount(c.cfg.Settings)
	}
	if c.eventQueueSize <= 0 {
		c.eventQueueSize = defaultETWQueueSize
	}
	if c.eventQueue == nil {
		c.eventQueue = make(chan *etwEventEnvelope, c.eventQueueSize)
	}
	ctx, cancel := context.WithCancel(context.Background())
	c.workerCtx = ctx
	c.workerCancel = cancel
	if c.monitor == nil {
		c.monitor = newDefaultETWMonitor()
	}
	c.monitor.SetWorkerTotal(c.workerCount)
	c.monitor.Start()
	for i := 0; i < c.workerCount; i++ {
		c.workerWG.Add(1)
		go c.eventWorker(ctx)
	}
}

func (c *etwCollector) eventWorker(ctx context.Context) {
	defer c.workerWG.Done()
	for {
		select {
		case env := <-c.eventQueue:
			if env == nil {
				continue
			}
			if c.monitor != nil {
				c.monitor.WorkerStarted()
			}
			c.processClonedRecord(&env.record)
			if c.monitor != nil {
				c.monitor.WorkerFinished()
				c.monitor.RecordQueueDepth(len(c.eventQueue))
			}
			c.eventPool.Put(env)
		case <-ctx.Done():
			select {
			case env := <-c.eventQueue:
				if env == nil {
					continue
				}
				if c.monitor != nil {
					c.monitor.WorkerStarted()
				}
				c.processClonedRecord(&env.record)
				if c.monitor != nil {
					c.monitor.WorkerFinished()
					c.monitor.RecordQueueDepth(len(c.eventQueue))
				}
				c.eventPool.Put(env)
			default:
				return
			}
		}
	}
}

func (c *etwCollector) enqueueEnvelope(env *etwEventEnvelope) bool {
	if c.eventQueue == nil {
		return false
	}
	select {
	case c.eventQueue <- env:
		if c.monitor != nil {
			c.monitor.RecordQueueDepth(len(c.eventQueue))
		}
		return true
	default:
		atomic.AddUint64(&c.queueDropped, 1)
		atomic.AddUint64(&c.eventsFiltered, 1)
		if c.monitor != nil {
			c.monitor.RecordDropped()
			c.monitor.RecordQueueDepth(len(c.eventQueue))
		}
		return false
	}
}

func (c *etwCollector) processClonedRecord(record *eventRecord) {
	if record == nil {
		return
	}
	var event *SystemEvent
	var err error
	provider := ""
	if record.EventHeader.ProviderId != (windows.GUID{}) {
		provider = record.EventHeader.ProviderId.String()
	}
	if c.parserManager != nil {
		event, err = c.parserManager.ParseEvent(provider, record)
	} else {
		event = convertEventRecord(record)
	}
	if err != nil {
		atomic.AddUint64(&c.eventsErrored, 1)
		c.stateMu.Lock()
		c.lastError = err.Error()
		c.stateMu.Unlock()
		return
	}
	if event == nil {
		return
	}
	if c.filterEngine != nil && !c.filterEngine.ShouldProcess(event) {
		atomic.AddUint64(&c.eventsFiltered, 1)
		return
	}
	if c.sampler != nil && !c.sampler.ShouldSample(event.EventType, event.Metadata) {
		atomic.AddUint64(&c.eventsFiltered, 1)
		return
	}
	if !c.runProcessors(event) {
		return
	}
	if detection := c.detectEvent(event); detection != nil {
		c.handleDetection(event, detection)
	}
	latency := time.Duration(0)
	if !event.Timestamp.IsZero() {
		latency = time.Since(event.Timestamp)
		if latency < 0 {
			latency = 0
		}
	}
	delay := uint64(latency.Microseconds())
	atomic.StoreUint64(&c.latencyLastMicros, delay)
	for {
		old := atomic.LoadUint64(&c.latencyMaxMicros)
		if delay <= old || atomic.CompareAndSwapUint64(&c.latencyMaxMicros, old, delay) {
			break
		}
	}
	if c.monitor != nil {
		c.monitor.RecordProcessed(latency)
	}
	h := c.handler
	if h == nil {
		return
	}
	if err := h.HandleEvent(context.Background(), event); err != nil {
		atomic.AddUint64(&c.eventsErrored, 1)
		c.stateMu.Lock()
		c.lastError = err.Error()
		c.stateMu.Unlock()
		return
	}
	atomic.AddUint64(&c.eventsEmitted, 1)
}

func (c *etwCollector) cloneEventRecord(record *eventRecord) *etwEventEnvelope {
	if record == nil {
		return nil
	}
	raw := c.eventPool.Get()
	if raw == nil {
		raw = &etwEventEnvelope{}
	}
	env := raw.(*etwEventEnvelope)
	env.record = *record
	if record.UserDataLength > 0 && record.UserData != 0 {
		length := int(record.UserDataLength)
		if cap(env.userBuf) < length {
			env.userBuf = make([]byte, length)
		}
		env.userBuf = env.userBuf[:length]
		src := unsafe.Slice((*byte)(unsafe.Pointer(record.UserData)), length)
		copy(env.userBuf, src)
		env.record.UserData = uintptr(unsafe.Pointer(&env.userBuf[0]))
	} else {
		env.userBuf = env.userBuf[:0]
		env.record.UserData = 0
		env.record.UserDataLength = 0
	}
	env.record.UserContext = 0
	return env
}

func (c *etwCollector) stopWorkerPool() {
	cancel := c.workerCancel
	if cancel != nil {
		cancel()
	}
	c.workerWG.Wait()
	if c.eventQueue != nil {
		for {
			select {
			case env := <-c.eventQueue:
				if env != nil {
					c.eventPool.Put(env)
				}
			default:
				goto drained
			}
		}
	}
drained:
	if c.monitor != nil {
		c.monitor.RecordQueueDepth(0)
		c.monitor.Stop()
	}
	c.workerCtx = nil
	c.workerCancel = nil
}

func isIgnorableControlError(err error) bool {
	if errno, ok := err.(windows.Errno); ok {
		return errno == errorWmiInstanceNotFound
	}
	return false
}

func newEventTraceProperties() *eventTraceProperties {
	return &eventTraceProperties{
		Wnode: wnodeHeader{},
	}
}

func (c *etwCollector) processTraceLoop(ctx context.Context) {
	defer c.stopWorkerPool()
	logfile := newEventTraceLogfile(c.name, c)
	c.stateMu.Lock()
	c.traceLogfile = logfile
	c.stateMu.Unlock()
	traceHandle, err := openTrace(logfile)
	if err != nil {
		c.stateMu.Lock()
		c.lastError = err.Error()
		c.stateMu.Unlock()
		return
	}
	c.stateMu.Lock()
	c.traceHandle = traceHandle
	c.stateMu.Unlock()
	defer func() {
		closeTrace(traceHandle)
		c.stateMu.Lock()
		c.traceHandle = 0
		c.traceLogfile = nil
		c.stateMu.Unlock()
	}()
	r1, _, e1 := procProcessTrace.Call(uintptr(unsafe.Pointer(&traceHandle)), 1, 0, 0)
	if r1 != windows.ERROR_SUCCESS && e1 != windows.ERROR_CANCELLED && e1 != 0 {
		c.stateMu.Lock()
		c.lastError = e1.Error()
		c.stateMu.Unlock()
	}
}

func (c *etwCollector) handleEventRecord(record *eventRecord) {
	if record == nil {
		return
	}
	if c.eventQueue == nil {
		c.processClonedRecord(record)
		return
	}
	env := c.cloneEventRecord(record)
	if env == nil {
		return
	}
	if c.enqueueEnvelope(env) {
		return
	}
	// Fallback to inline processing when enqueue fails.
	c.processClonedRecord(&env.record)
	c.eventPool.Put(env)
}

func (c *etwCollector) UpdateConfig(cfg Config) {
	c.stateMu.Lock()
	c.cfg = cfg
	c.stateMu.Unlock()
	c.applyConfig(cfg)
}

func (c *etwCollector) SetDetectionSink(sink DetectionSink) {
	c.stateMu.Lock()
	c.detectionSink = sink
	c.stateMu.Unlock()
}

func (c *etwCollector) applyConfig(cfg Config) {
	parserCfg := cfg.Parser
	var pluginNames []string
	if c.pluginLoader != nil {
		parsers, processors, names, err := c.pluginLoader.Load(parserCfg.Plugins)
		if err != nil {
			c.stateMu.Lock()
			c.lastError = err.Error()
			c.stateMu.Unlock()
		} else {
			for _, parser := range parsers {
				c.parserManager.RegisterParser(parser)
			}
			c.eventProcessors = processors
			pluginNames = names
		}
	}
	if pluginNames != nil {
		removed := c.replacePluginNames(pluginNames)
		if len(removed) > 0 {
			parserCfg.Disabled = appendUniqueStrings(parserCfg.Disabled, removed)
		}
	}
	if c.parserManager != nil {
		_ = c.parserManager.UpdateConfig(parserCfg)
	}
	if c.filterEngine != nil {
		_ = c.filterEngine.UpdateConfig(cfg.Filters)
	}
	if c.sampler != nil {
		_ = c.sampler.UpdateConfig(cfg.Sampling)
	}
}

type enableTraceParameters struct {
	Version          uint32
	EnableProperty   uint32
	ControlFlags     uint32
	SourceID         windows.GUID
	EnableFilterDesc uintptr
	FilterDescCount  uint32
}

type eventTraceProperties struct {
	Wnode               wnodeHeader
	BufferSize          uint32
	MinimumBuffers      uint32
	MaximumBuffers      uint32
	MaximumFileSize     uint32
	LogFileMode         uint32
	FlushTimer          uint32
	EnableFlags         uint32
	AgeLimit            int32
	NumberOfBuffers     uint32
	FreeBuffers         uint32
	EventsLost          uint32
	BuffersWritten      uint32
	LogBuffersLost      uint32
	RealTimeBuffersLost uint32
	LoggerThreadID      windows.Handle
	LogFileNameOffset   uint32
	LoggerNameOffset    uint32
}

type wnodeHeader struct {
	BufferSize        uint32
	ProviderID        uint32
	HistoricalContext uint64
	TimeStamp         windows.Filetime
	Guid              windows.GUID
	ClientContext     uint32
	Flags             uint32
}

var eventRecordCallbackPtr = windows.NewCallback(func(record *eventRecord) uintptr {
	if record == nil || record.UserContext == 0 {
		return 0
	}
	collector := (*etwCollector)(unsafe.Pointer(record.UserContext))
	collector.handleEventRecord(record)
	return 0
})

func newEventTraceLogfile(name string, c *etwCollector) *eventTraceLogfile {
	loggerName, _ := windows.UTF16PtrFromString(name)
	return &eventTraceLogfile{
		LoggerName:          loggerName,
		ProcessTraceMode:    processTraceModeRealtime | processTraceModeEventRecord,
		EventRecordCallback: eventRecordCallbackPtr,
		Context:             uintptr(unsafe.Pointer(c)),
	}
}

func openTrace(logfile *eventTraceLogfile) (windows.Handle, error) {
	handle, _, err := procOpenTraceW.Call(uintptr(unsafe.Pointer(logfile)))
	if handle == invalidProcessTraceHandle {
		if err != windows.ERROR_SUCCESS {
			return 0, err
		}
		return 0, windows.Errno(windows.ERROR_INVALID_HANDLE)
	}
	return windows.Handle(handle), nil
}

func closeTrace(handle windows.Handle) error {
	if handle == 0 {
		return nil
	}
	r1, _, e1 := procCloseTrace.Call(uintptr(handle))
	if r1 != windows.ERROR_SUCCESS {
		if e1 != windows.ERROR_SUCCESS {
			return e1
		}
		return windows.Errno(r1)
	}
	return nil
}

func convertEventRecord(record *eventRecord) *SystemEvent {
	header := record.EventHeader
	event := &SystemEvent{
		EventType: fmt.Sprintf("%d", header.EventDescriptor.Id),
		Source:    strings.ToLower(header.ProviderId.String()),
		Timestamp: filetimeToTime(header.TimeStamp),
		Metadata: map[string]string{
			"level":   fmt.Sprintf("%d", header.EventDescriptor.Level),
			"opcode":  fmt.Sprintf("%d", header.EventDescriptor.Opcode),
			"task":    fmt.Sprintf("%d", header.EventDescriptor.Task),
			"channel": fmt.Sprintf("%d", header.EventDescriptor.Channel),
		},
		Payload: map[string]any{
			"thread_id":  header.ThreadId,
			"process_id": header.ProcessId,
		},
	}
	if record.UserDataLength > 0 && record.UserData != 0 {
		event.Payload["user_data_hex"] = hex.EncodeToString(unsafe.Slice((*byte)(unsafe.Pointer(record.UserData)), int(record.UserDataLength)))
	}
	return event
}

func filetimeToTime(ft windows.Filetime) time.Time {
	return time.Unix(0, ft.Nanoseconds())
}

func determineETWWorkerCount(settings map[string]any) int {
	defaultCount := runtime.NumCPU()
	if defaultCount < 1 {
		defaultCount = 1
	}
	count := resolveIntSetting(settings, "worker_count", defaultCount)
	if count < 1 {
		count = 1
	}
	if count > 64 {
		count = 64
	}
	return count
}

func determineETWQueueSize(settings map[string]any) int {
	size := resolveIntSetting(settings, "queue_size", defaultETWQueueSize)
	if size < 256 {
		size = 256
	}
	return size
}

func resolveIntSetting(settings map[string]any, key string, fallback int) int {
	if settings == nil {
		return fallback
	}
	raw, ok := settings[key]
	if !ok {
		return fallback
	}
	switch v := raw.(type) {
	case int:
		return v
	case int32:
		return int(v)
	case int64:
		return int(v)
	case float64:
		return int(v)
	case string:
		if parsed, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
			return parsed
		}
	}
	return fallback
}

func appendUniqueStrings(base []string, items []string) []string {
	if len(items) == 0 {
		return base
	}
	seen := make(map[string]struct{}, len(base))
	for _, val := range base {
		seen[val] = struct{}{}
	}
	for _, item := range items {
		if _, ok := seen[item]; ok {
			continue
		}
		base = append(base, item)
		seen[item] = struct{}{}
	}
	return base
}

func (c *etwCollector) replacePluginNames(names []string) []string {
	if c.activePluginNames == nil {
		c.activePluginNames = make(map[string]struct{})
	}
	removed := make([]string, 0)
	newSet := make(map[string]struct{}, len(names))
	for _, name := range names {
		newSet[name] = struct{}{}
	}
	for name := range c.activePluginNames {
		if _, ok := newSet[name]; !ok {
			removed = append(removed, name)
		}
	}
	c.activePluginNames = newSet
	return removed
}

func (c *etwCollector) runProcessors(event *SystemEvent) bool {
	if len(c.eventProcessors) == 0 || event == nil {
		return true
	}
	for _, processor := range c.eventProcessors {
		if processor == nil {
			continue
		}
		cont, err := processor.Process(context.Background(), event)
		if err != nil {
			atomic.AddUint64(&c.eventsErrored, 1)
		}
		if cont {
			c.processorStats.RecordProcessed()
			continue
		}
		c.processorStats.RecordDropped()
		atomic.AddUint64(&c.eventsFiltered, 1)
		return false
	}
	return true
}

func (c *etwCollector) detectEvent(event *SystemEvent) *DetectionResult {
	if c.detectionEngine == nil || event == nil {
		return nil
	}
	return c.detectionEngine.Evaluate(event)
}

func (c *etwCollector) handleDetection(event *SystemEvent, result *DetectionResult) {
	if event == nil || result == nil {
		return
	}
	if event.Metadata == nil {
		event.Metadata = make(map[string]string)
	}
	event.Metadata["detection.rule"] = result.RuleID
	event.Metadata["detection.name"] = result.Name
	event.Metadata["detection.severity"] = result.Severity
	event.Metadata["detection.action"] = string(result.Action)
	if result.Description != "" {
		event.Metadata["detection.description"] = result.Description
	}
	if result.Tags != nil {
		if event.Tags == nil {
			event.Tags = make(map[string]string)
		}
		for k, v := range result.Tags {
			event.Tags[k] = v
		}
	}
	if result.Metadata != nil {
		for k, v := range result.Metadata {
			event.Metadata[k] = v
		}
	}
	if event.Tags == nil {
		event.Tags = make(map[string]string)
	}
	event.Tags["detection"] = "true"
	sink := c.detectionSink
	if sink != nil {
		resCopy := *result
		go sink.OnDetection(context.Background(), cloneSystemEvent(event), resCopy)
	}
}

type eventTraceLogfile struct {
	LogFileName         *uint16
	LoggerName          *uint16
	CurrentTime         int64
	BuffersRead         uint32
	ProcessTraceMode    uint32
	CurrentEvent        uintptr
	LogfileHeader       [84]byte
	BufferCallback      uintptr
	BufferSize          uint32
	Filled              uint32
	EventsLost          uint32
	EventCallback       uintptr
	EventRecordCallback uintptr
	Context             uintptr
}

type eventRecord struct {
	EventHeader       eventHeader
	BufferContext     bufferContext
	ExtendedDataCount uint16
	UserDataLength    uint16
	ExtendedData      uintptr
	UserData          uintptr
	UserContext       uintptr
}

type eventHeader struct {
	Size            uint16
	HeaderType      uint16
	Flags           uint16
	EventProperty   uint16
	ThreadId        uint32
	ProcessId       uint32
	TimeStamp       windows.Filetime
	ProviderId      windows.GUID
	EventDescriptor eventDescriptor
	KernelTime      uint32
	UserTime        uint32
	ActivityId      windows.GUID
}

type eventDescriptor struct {
	Id      uint16
	Version uint8
	Channel uint8
	Level   uint8
	Opcode  uint8
	Task    uint16
	Keyword uint64
}

type bufferContext struct {
	ProcessorIndex uint8
	LoggerId       uint8
	Alignment      uint16
	KernelTime     uint32
	UserTime       uint32
}

type etwEventEnvelope struct {
	record  eventRecord
	userBuf []byte
}
