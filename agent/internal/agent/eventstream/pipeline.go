package eventstream

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/m-sec-org/d-eyes/agent/internal/collector"
)

const (
	defaultQueueSize   = 256
	defaultChunkEvents = 64
	defaultChunkBytes  = 64 * 1024
)

type Pipeline struct {
	queue     chan []byte
	diskDir   string
	seq       atomic.Uint64
	dropped   atomic.Uint64
	diskSeq   atomic.Uint64
	diskFiles atomic.Uint64

	maxChunkEvents int
	maxChunkBytes  int

	diskMu sync.Mutex
}

type Stats struct {
	QueueDepth  int
	DiskBacklog uint64
	Dropped     uint64
}

func NewPipeline(queueSize int, cacheDir string) (*Pipeline, error) {
	if queueSize <= 0 {
		queueSize = defaultQueueSize
	}
	dir := filepath.Join(cacheDir, "events")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("create event cache dir: %w", err)
	}
	return &Pipeline{
		queue:          make(chan []byte, queueSize),
		diskDir:        dir,
		maxChunkEvents: defaultChunkEvents,
		maxChunkBytes:  defaultChunkBytes,
	}, nil
}

func (p *Pipeline) Handler() collector.EventHandler {
	if p == nil {
		return collector.EventHandlerFunc(func(context.Context, *collector.SystemEvent) error { return nil })
	}
	return collector.EventHandlerFunc(func(_ context.Context, event *collector.SystemEvent) error {
		return p.Handle(event)
	})
}

func (p *Pipeline) Handle(event *collector.SystemEvent) error {
	if p == nil || event == nil {
		return nil
	}
	payload, err := p.marshalEvent(event)
	if err != nil {
		p.dropped.Add(1)
		return err
	}
	select {
	case p.queue <- payload:
	default:
		if err := p.persistToDisk(payload); err != nil {
			p.dropped.Add(1)
			return err
		}
	}
	return nil
}

func (p *Pipeline) marshalEvent(event *collector.SystemEvent) ([]byte, error) {
	if event == nil {
		return nil, fmt.Errorf("nil event")
	}
	metadata := cloneStringMap(event.Metadata)
	collectorName := metadata["collector"]
	if collectorName == "" {
		collectorName = event.Source
	}
	collectorKind := metadata["collector_kind"]
	envelope := map[string]any{
		"uuid":       uuid.New().String(),
		"collector":  collectorName,
		"event_type": event.EventType,
		"source":     event.Source,
		"timestamp":  event.Timestamp.UTC().Format(time.RFC3339Nano),
	}
	if collectorKind != "" {
		envelope["collector_kind"] = collectorKind
	}
	if len(event.Payload) > 0 {
		envelope["payload"] = event.Payload
	}
	if len(metadata) > 0 {
		envelope["metadata"] = metadata
	}
	if len(event.Tags) > 0 {
		envelope["tags"] = event.Tags
	}
	if len(event.Raw) > 0 {
		envelope["raw"] = event.Raw
	}
	if event.Sequence > 0 {
		envelope["sequence"] = event.Sequence
	} else {
		envelope["sequence"] = p.seq.Add(1)
	}
	return json.Marshal(envelope)
}

func (p *Pipeline) NextChunk() (string, int) {
	batch, count := p.NextJSONBatch()
	if count == 0 {
		return "", 0
	}
	encoded := base64.StdEncoding.EncodeToString(batch)
	return encoded, count
}

// NextJSONBatch returns a JSON array encoded batch of events along with count.
func (p *Pipeline) NextJSONBatch() ([]byte, int) {
	if p == nil {
		return nil, 0
	}
	events, totalBytes := p.collectEvents()
	if len(events) == 0 {
		return nil, 0
	}
	chunk := make([]byte, 0, totalBytes+len(events)*2)
	chunk = append(chunk, '[')
	for i, evt := range events {
		if i > 0 {
			chunk = append(chunk, ',')
		}
		chunk = append(chunk, evt...)
	}
	chunk = append(chunk, ']')
	return chunk, len(events)
}

func (p *Pipeline) pullFromDisk(maxEvents int, maxBytes int) [][]byte {
	p.diskMu.Lock()
	defer p.diskMu.Unlock()
	entries, err := os.ReadDir(p.diskDir)
	if err != nil || len(entries) == 0 {
		return nil
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Name() < entries[j].Name()
	})
	batch := make([][]byte, 0, maxEvents)
	total := 0
	for _, entry := range entries {
		if len(batch) >= maxEvents || total >= maxBytes {
			break
		}
		if entry.IsDir() {
			continue
		}
		path := filepath.Join(p.diskDir, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		if err := os.Remove(path); err == nil {
			if p.diskFiles.Load() > 0 {
				p.diskFiles.Add(^uint64(0))
			}
		}
		batch = append(batch, data)
		total += len(data)
	}
	return batch
}

func (p *Pipeline) collectEvents() ([][]byte, int) {
	events := make([][]byte, 0, p.maxChunkEvents)
	totalBytes := 0
	diskBatch := p.pullFromDisk(p.maxChunkEvents, p.maxChunkBytes)
	for _, data := range diskBatch {
		if len(events) >= p.maxChunkEvents || totalBytes+len(data) > p.maxChunkBytes {
			_ = p.persistToDisk(data)
			continue
		}
		events = append(events, data)
		totalBytes += len(data)
	}

drainQueue:
	for len(events) < p.maxChunkEvents && totalBytes < p.maxChunkBytes {
		select {
		case data := <-p.queue:
			if len(data) == 0 {
				continue
			}
			if totalBytes+len(data) > p.maxChunkBytes {
				_ = p.persistToDisk(data)
				continue
			}
			events = append(events, data)
			totalBytes += len(data)
		default:
			break drainQueue
		}
	}
	return events, totalBytes
}

// RequeueBatch persists a drained JSON batch back to disk for retry.
func (p *Pipeline) RequeueBatch(batch []byte) {
	if p == nil || len(batch) == 0 {
		return
	}
	var events []json.RawMessage
	if err := json.Unmarshal(batch, &events); err != nil {
		_ = p.persistToDisk(batch)
		return
	}
	for _, evt := range events {
		_ = p.persistToDisk([]byte(evt))
	}
}

func (p *Pipeline) persistToDisk(data []byte) error {
	if len(data) == 0 {
		return nil
	}
	p.diskMu.Lock()
	defer p.diskMu.Unlock()
	filename := fmt.Sprintf("event-%d-%d.json", time.Now().UnixNano(), p.diskSeq.Add(1))
	path := filepath.Join(p.diskDir, filename)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return err
	}
	p.diskFiles.Add(1)
	return nil
}

func (p *Pipeline) Stats() Stats {
	if p == nil {
		return Stats{}
	}
	return Stats{
		QueueDepth:  len(p.queue),
		DiskBacklog: p.diskFiles.Load(),
		Dropped:     p.dropped.Load(),
	}
}

func cloneStringMap(src map[string]string) map[string]string {
	if len(src) == 0 {
		return nil
	}
	dst := make(map[string]string, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}
