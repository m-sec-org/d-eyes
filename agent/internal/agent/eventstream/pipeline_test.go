package eventstream

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/m-sec-org/d-eyes/agent/internal/collector"
)

func newTestPipeline(t *testing.T, queueSize int) *Pipeline {
	t.Helper()
	dir := t.TempDir()
	pl, err := NewPipeline(queueSize, dir)
	require.NoError(t, err)
	pl.maxChunkEvents = 4
	pl.maxChunkBytes = 8 * 1024
	return pl
}

func TestPipelineNextChunk(t *testing.T) {
	pl := newTestPipeline(t, 4)
	event := &collector.SystemEvent{
		EventType: "process.exec",
		Source:    "ebpf",
		Timestamp: time.Now(),
		Metadata: map[string]string{
			"collector":      "ebpf-test",
			"collector_kind": string(collector.KindEBPF),
		},
		Payload: map[string]any{
			"pid": 1234,
		},
	}
	require.NoError(t, pl.Handle(event))
	chunk, count := pl.NextChunk()
	require.NotEmpty(t, chunk)
	require.Equal(t, 1, count)
	raw, err := base64.StdEncoding.DecodeString(chunk)
	require.NoError(t, err)
	var events []map[string]any
	require.NoError(t, json.Unmarshal(raw, &events))
	require.Len(t, events, 1)
	require.Equal(t, "ebpf-test", events[0]["collector"])
}

func TestPipelineSpillsToDisk(t *testing.T) {
	pl := newTestPipeline(t, 1)
	event := func(pid int) *collector.SystemEvent {
		return &collector.SystemEvent{
			EventType: "process.exec",
			Source:    "ebpf",
			Timestamp: time.Now(),
			Metadata:  map[string]string{"collector": "diag-ebpf"},
			Payload:   map[string]any{"pid": pid},
		}
	}
	require.NoError(t, pl.Handle(event(1)))
	require.NoError(t, pl.Handle(event(2)))
	require.GreaterOrEqual(t, pl.diskFiles.Load(), uint64(1))
	chunk, count := pl.NextChunk()
	require.NotEmpty(t, chunk)
	require.Equal(t, 2, count)
	require.Equal(t, uint64(0), pl.diskFiles.Load())
}

func TestPipelineStats(t *testing.T) {
	pl := newTestPipeline(t, 2)
	require.NoError(t, pl.Handle(&collector.SystemEvent{
		EventType: "process.exec",
		Source:    "ebpf",
		Timestamp: time.Now(),
		Metadata:  map[string]string{"collector": "diag-ebpf"},
	}))
	stats := pl.Stats()
	require.Equal(t, 1, stats.QueueDepth)
	require.Equal(t, uint64(0), stats.DiskBacklog)
	require.Equal(t, uint64(0), stats.Dropped)
}

func TestPipelinePersistFailureDropsEvent(t *testing.T) {
	dir := t.TempDir()
	pl, err := NewPipeline(1, dir)
	require.NoError(t, err)
	require.NoError(t, pl.Handle(&collector.SystemEvent{
		EventType: "process.exec",
		Source:    "ebpf",
		Timestamp: time.Now(),
	}))
	// Remove cache dir to trigger persist failure.
	require.NoError(t, os.RemoveAll(filepath.Join(dir, "events")))
	err = pl.Handle(&collector.SystemEvent{
		EventType: "process.exit",
		Source:    "ebpf",
		Timestamp: time.Now(),
	})
	require.Error(t, err)
	require.Equal(t, uint64(1), pl.dropped.Load())
}

func TestPipelineNextJSONBatchAndRequeue(t *testing.T) {
	pl := newTestPipeline(t, 4)
	require.NoError(t, pl.Handle(&collector.SystemEvent{EventType: "process.exec", Source: "ebpf", Timestamp: time.Now()}))
	batch, count := pl.NextJSONBatch()
	require.Equal(t, 1, count)
	require.Contains(t, string(batch), "process.exec")
	require.Equal(t, 0, pl.Stats().QueueDepth)
	pl.RequeueBatch(batch)
	reqBatch, reqCount := pl.NextJSONBatch()
	require.Equal(t, string(batch), string(reqBatch))
	require.Equal(t, count, reqCount)
}
