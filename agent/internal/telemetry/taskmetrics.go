package telemetry

import (
	"fmt"
	"os"
	"runtime"
	"time"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/net"
	"github.com/shirou/gopsutil/v4/process"

	sharedtelemetry "github.com/m-sec-org/d-eyes/server/pkg/telemetry"
)

// TaskResourceStats describes resource usage during a task execution window.
type TaskResourceStats struct {
	CPUPercent     float64 `json:"cpu_percent"`
	MemoryBytes    uint64  `json:"memory_bytes"`
	MemoryPercent  float64 `json:"memory_percent"`
	IOReadBytes    uint64  `json:"io_read_bytes"`
	IOWriteBytes   uint64  `json:"io_write_bytes"`
	NetBytesSent   uint64  `json:"net_bytes_sent"`
	NetBytesRecv   uint64  `json:"net_bytes_recv"`
	DurationMillis int64   `json:"duration_ms"`
}

// TaskResourceTracker captures process resource deltas across a time window.
type TaskResourceTracker struct {
	proc      *process.Process
	startCPU  *cpu.TimesStat
	startIO   *process.IOCountersStat
	startNet  map[string]net.IOCountersStat
	startTime time.Time
}

// NewTaskResourceTracker initialises a tracker using the current agent process.
func NewTaskResourceTracker() *TaskResourceTracker {
	pid := int32(os.Getpid())
	proc, err := process.NewProcess(pid)
	tracker := &TaskResourceTracker{startTime: time.Now()}
	if err != nil {
		return tracker
	}
	tracker.proc = proc
	if times, err := proc.Times(); err == nil {
		tracker.startCPU = times
	}
	if ioCounters, err := proc.IOCounters(); err == nil {
		tracker.startIO = ioCounters
	}
	if netCounters, err := net.IOCounters(false); err == nil {
		tracker.startNet = snapshotNetCounters(netCounters)
	}
	return tracker
}

// Snapshot computes the resource deltas since tracker creation.
func (t *TaskResourceTracker) Snapshot() TaskResourceStats {
	stats := TaskResourceStats{DurationMillis: time.Since(t.startTime).Milliseconds()}
	proc := t.proc
	if proc == nil {
		return stats
	}
	if times, err := proc.Times(); err == nil && t.startCPU != nil {
		delta := cpuTotal(times) - cpuTotal(t.startCPU)
		duration := time.Since(t.startTime).Seconds()
		if duration > 0 {
			stats.CPUPercent = (delta / duration) * 100 / float64(runtime.NumCPU())
		}
	}
	if mem, err := proc.MemoryInfo(); err == nil && mem != nil {
		stats.MemoryBytes = mem.RSS
	}
	if memPercent, err := proc.MemoryPercent(); err == nil {
		stats.MemoryPercent = float64(memPercent)
	}
	if ioCounters, err := proc.IOCounters(); err == nil && ioCounters != nil && t.startIO != nil {
		stats.IOReadBytes = diffUint64(ioCounters.ReadBytes, t.startIO.ReadBytes)
		stats.IOWriteBytes = diffUint64(ioCounters.WriteBytes, t.startIO.WriteBytes)
	}
	if netCounters, err := net.IOCounters(false); err == nil && len(netCounters) > 0 {
		sent, recv := diffNetCounters(t.startNet, netCounters)
		stats.NetBytesSent = sent
		stats.NetBytesRecv = recv
	}
	return stats
}

func cpuTotal(times *cpu.TimesStat) float64 {
	if times == nil {
		return 0
	}
	return times.User + times.System
}

func diffUint64(curr, prev uint64) uint64 {
	if curr >= prev {
		return curr - prev
	}
	return 0
}

func snapshotNetCounters(list []net.IOCountersStat) map[string]net.IOCountersStat {
	if len(list) == 0 {
		return nil
	}
	snapshot := make(map[string]net.IOCountersStat, len(list))
	for _, item := range list {
		snapshot[item.Name] = item
	}
	return snapshot
}

func diffNetCounters(start map[string]net.IOCountersStat, current []net.IOCountersStat) (sent uint64, recv uint64) {
	if len(current) == 0 || start == nil {
		return 0, 0
	}
	for _, item := range current {
		if base, ok := start[item.Name]; ok {
			sent += diffUint64(item.BytesSent, base.BytesSent)
			recv += diffUint64(item.BytesRecv, base.BytesRecv)
		}
	}
	return
}

// AppendTaskResourceMetadata encodes and stores task resource stats into metadata map.
func AppendTaskResourceMetadata(meta map[string]string, stats TaskResourceStats) map[string]string {
	if meta == nil {
		meta = make(map[string]string)
	}
	if stats.DurationMillis <= 0 && stats.CPUPercent == 0 && stats.MemoryBytes == 0 && stats.NetBytesRecv == 0 && stats.NetBytesSent == 0 {
		return meta
	}
	payload, err := encodePayload(stats)
	if err == nil && payload != "" {
		meta[sharedtelemetry.MetadataTaskResources] = payload
	}
	meta["telemetry.task.cpu_percent"] = fmt.Sprintf("%.2f", stats.CPUPercent)
	meta["telemetry.task.mem_bytes"] = fmt.Sprintf("%d", stats.MemoryBytes)
	meta["telemetry.task.mem_percent"] = fmt.Sprintf("%.2f", stats.MemoryPercent)
	meta["telemetry.task.io_read_bytes"] = fmt.Sprintf("%d", stats.IOReadBytes)
	meta["telemetry.task.io_write_bytes"] = fmt.Sprintf("%d", stats.IOWriteBytes)
	meta["telemetry.task.net_bytes_sent"] = fmt.Sprintf("%d", stats.NetBytesSent)
	meta["telemetry.task.net_bytes_recv"] = fmt.Sprintf("%d", stats.NetBytesRecv)
	meta["telemetry.task.duration_ms"] = fmt.Sprintf("%d", stats.DurationMillis)
	return meta
}
