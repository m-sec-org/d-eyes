package collector

import (
	"runtime"
	"sync/atomic"
	"time"
)

// ETWMonitor captures runtime metrics for the ETW collector pipeline.
type ETWMonitor interface {
	Start()
	Stop()
	SetWorkerTotal(total int)
	WorkerStarted()
	WorkerFinished()
	RecordProcessed(latency time.Duration)
	RecordDropped()
	RecordQueueDepth(depth int)
	GetMetrics() ETWMetrics
}

// ETWMetrics conveys collector runtime statistics.
type ETWMetrics struct {
	CPUUsage        float64
	MemoryUsage     uint64
	DiskIO          uint64
	EventsProcessed uint64
	EventsDropped   uint64
	EventLatencyAvg time.Duration
	EventLatencyMax time.Duration
	QueueDepth      int
	WorkersBusy     int
}

type defaultETWMonitor struct {
	workersTotal atomic.Int64
	workersBusy  atomic.Int64
	processed    atomic.Uint64
	dropped      atomic.Uint64
	totalLatency atomic.Int64 // microseconds
	latencyMax   atomic.Int64 // microseconds
	queueDepth   atomic.Int64
	running      atomic.Bool
}

func newDefaultETWMonitor() *defaultETWMonitor {
	return &defaultETWMonitor{}
}

func (m *defaultETWMonitor) Start() {
	m.running.Store(true)
}

func (m *defaultETWMonitor) Stop() {
	m.running.Store(false)
	m.queueDepth.Store(0)
	m.workersBusy.Store(0)
}

func (m *defaultETWMonitor) SetWorkerTotal(total int) {
	if total < 0 {
		total = 0
	}
	m.workersTotal.Store(int64(total))
}

func (m *defaultETWMonitor) WorkerStarted() {
	m.workersBusy.Add(1)
}

func (m *defaultETWMonitor) WorkerFinished() {
	for {
		current := m.workersBusy.Load()
		if current <= 0 {
			return
		}
		if m.workersBusy.CompareAndSwap(current, current-1) {
			return
		}
	}
}

func (m *defaultETWMonitor) RecordProcessed(latency time.Duration) {
	if latency < 0 {
		latency = 0
	}
	m.processed.Add(1)
	micro := latency.Microseconds()
	m.totalLatency.Add(micro)
	for {
		prev := m.latencyMax.Load()
		if micro <= prev || m.latencyMax.CompareAndSwap(prev, micro) {
			break
		}
	}
}

func (m *defaultETWMonitor) RecordDropped() {
	m.dropped.Add(1)
}

func (m *defaultETWMonitor) RecordQueueDepth(depth int) {
	if depth < 0 {
		depth = 0
	}
	m.queueDepth.Store(int64(depth))
}

func (m *defaultETWMonitor) GetMetrics() ETWMetrics {
	processed := m.processed.Load()
	totalLatency := m.totalLatency.Load()
	avg := time.Duration(0)
	if processed > 0 {
		avg = time.Duration(totalLatency/int64(processed)) * time.Microsecond
	}
	max := time.Duration(m.latencyMax.Load()) * time.Microsecond
	workersBusy := int(m.workersBusy.Load())
	workersTotal := m.workersTotal.Load()
	cpuUsage := 0.0
	if workersTotal > 0 {
		cpuUsage = float64(workersBusy) / float64(workersTotal)
	}
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	return ETWMetrics{
		CPUUsage:        cpuUsage,
		MemoryUsage:     mem.Alloc,
		EventsProcessed: processed,
		EventsDropped:   m.dropped.Load(),
		EventLatencyAvg: avg,
		EventLatencyMax: max,
		QueueDepth:      int(m.queueDepth.Load()),
		WorkersBusy:     workersBusy,
	}
}
