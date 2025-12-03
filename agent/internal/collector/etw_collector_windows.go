//go:build windows

package collector

import (
	"context"
	"encoding/hex"
	"fmt"
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
	latencyLastMicros uint64
	latencyMaxMicros  uint64
}

func newETWCollector(cfg Config) (EventCollector, error) {
	name := cfg.Name
	if strings.TrimSpace(name) == "" {
		name = defaultCollectorLogName
	}
	if len(name) > maxSessionNameLength {
		name = name[:maxSessionNameLength]
	}
	return &etwCollector{
		cfg:  cfg,
		name: name,
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
	handle, err := startTraceSession(c.name)
	if err != nil {
		c.lastError = err.Error()
		return err
	}
	if err := c.enableProviders(handle, c.cfg.Providers); err != nil {
		c.lastError = err.Error()
		_ = stopTraceSession(handle, c.name)
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
	return nil
}

func (c *etwCollector) Status() CollectorStatus {
	c.stateMu.RLock()
	defer c.stateMu.RUnlock()
	state := "stopped"
	if c.running {
		state = "running"
	}
	return CollectorStatus{
		Name:      c.Name(),
		Kind:      KindETW,
		State:     state,
		StartedAt: c.startedAt,
		LastError: c.lastError,
		Stats: map[string]any{
			"events_emitted":  atomic.LoadUint64(&c.eventsEmitted),
			"events_filtered": atomic.LoadUint64(&c.eventsFiltered),
			"events_errored":  atomic.LoadUint64(&c.eventsErrored),
			"latency_last_ms": float64(atomic.LoadUint64(&c.latencyLastMicros)) / 1000.0,
			"latency_max_ms":  float64(atomic.LoadUint64(&c.latencyMaxMicros)) / 1000.0,
		},
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
	event := convertEventRecord(record)
	if event == nil {
		return
	}
	if !c.matchesFilters(event) {
		atomic.AddUint64(&c.eventsFiltered, 1)
		return
	}
	delay := uint64(time.Since(event.Timestamp).Microseconds())
	atomic.StoreUint64(&c.latencyLastMicros, delay)
	for {
		old := atomic.LoadUint64(&c.latencyMaxMicros)
		if delay <= old || atomic.CompareAndSwapUint64(&c.latencyMaxMicros, old, delay) {
			break
		}
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

func (c *etwCollector) matchesFilters(event *SystemEvent) bool {
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
