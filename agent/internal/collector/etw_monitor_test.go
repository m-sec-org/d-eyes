package collector

import (
	"testing"
	"time"
)

func TestDefaultETWMonitorMetrics(t *testing.T) {
	monitor := newDefaultETWMonitor()
	monitor.SetWorkerTotal(4)
	monitor.Start()
	monitor.RecordQueueDepth(3)
	monitor.WorkerStarted()
	monitor.RecordProcessed(2 * time.Millisecond)
	monitor.WorkerFinished()
	monitor.RecordDropped()

	metrics := monitor.GetMetrics()
	if metrics.QueueDepth != 3 {
		t.Fatalf("expected queue depth 3, got %d", metrics.QueueDepth)
	}
	if metrics.WorkersBusy != 0 {
		t.Fatalf("workers busy should reset to 0, got %d", metrics.WorkersBusy)
	}
	if metrics.EventsProcessed != 1 {
		t.Fatalf("expected one processed event, got %d", metrics.EventsProcessed)
	}
	if metrics.EventsDropped != 1 {
		t.Fatalf("expected one dropped event, got %d", metrics.EventsDropped)
	}
	if metrics.EventLatencyAvg <= 0 {
		t.Fatalf("expected latency avg to be recorded")
	}
	if metrics.EventLatencyMax < metrics.EventLatencyAvg {
		t.Fatalf("max latency should be >= avg latency")
	}
	if metrics.CPUUsage < 0 || metrics.CPUUsage > 1 {
		t.Fatalf("cpu usage should be normalized, got %f", metrics.CPUUsage)
	}
	monitor.Stop()
	if metricsAfterStop := monitor.GetMetrics(); metricsAfterStop.QueueDepth != 0 {
		t.Fatalf("expected queue depth reset after stop")
	}
}
