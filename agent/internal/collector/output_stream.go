package collector

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

type httpClient interface {
	Do(*http.Request) (*http.Response, error)
}

var newStreamHTTPClient = func() httpClient {
	return &http.Client{Timeout: 15 * time.Second}
}

type streamWriter struct {
	cfg     CollectorStreamConfig
	client  httpClient
	events  chan *SystemEvent
	cancel  context.CancelFunc
	workers sync.WaitGroup
}

func newStreamWriter(cfg CollectorStreamConfig) (EventHandler, func(), error) {
	endpoint := strings.TrimSpace(cfg.URL)
	if endpoint == "" {
		return nil, nil, fmt.Errorf("stream output: url is required")
	}
	if cfg.MaxBatch <= 0 {
		cfg.MaxBatch = 64
	}
	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = time.Second
	}
	ctx, cancel := context.WithCancel(context.Background())
	writer := &streamWriter{
		cfg:    cfg,
		client: newStreamHTTPClient(),
		events: make(chan *SystemEvent, cfg.MaxBatch*4),
		cancel: cancel,
	}
	writer.workers.Add(1)
	go writer.run(ctx)
	handler := EventHandlerFunc(func(_ context.Context, event *SystemEvent) error {
		if event == nil {
			return nil
		}
		select {
		case writer.events <- cloneEvent(event):
			return nil
		default:
			return fmt.Errorf("stream output queue full for %s", endpoint)
		}
	})
	cleanup := func() {
		cancel()
		writer.workers.Wait()
	}
	return handler, cleanup, nil
}

func (s *streamWriter) run(ctx context.Context) {
	defer s.workers.Done()
	ticker := time.NewTicker(s.cfg.FlushInterval)
	defer ticker.Stop()
	batch := make([]*SystemEvent, 0, s.cfg.MaxBatch)
	flush := func() {
		if len(batch) == 0 {
			return
		}
		if err := s.upload(batch); err != nil {
			log.Printf("[collector] stream upload failed: %v", err)
		}
		batch = batch[:0]
	}
	for {
		select {
		case <-ctx.Done():
			flush()
			return
		case evt := <-s.events:
			if evt != nil {
				batch = append(batch, evt)
			}
			if len(batch) >= s.cfg.MaxBatch {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}

func (s *streamWriter) upload(events []*SystemEvent) error {
	body := struct {
		AgentID   string            `json:"agent_id,omitempty"`
		AgentName string            `json:"agent_name,omitempty"`
		Events    []*SystemEvent    `json:"events"`
		Metadata  map[string]string `json:"metadata,omitempty"`
	}{
		AgentID:   s.agentID(),
		AgentName: s.agentName(),
		Events:    events,
		Metadata:  map[string]string{"source": "collector.stream"},
	}
	data, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, s.cfg.URL, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if key := strings.TrimSpace(s.cfg.APIKey); key != "" {
		req.Header.Set("X-API-Key", key)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("stream upload rejected: %s %s", resp.Status, strings.TrimSpace(string(msg)))
	}
	return nil
}

func (s *streamWriter) agentID() string {
	if strings.TrimSpace(s.cfg.AgentID) != "" {
		return s.cfg.AgentID
	}
	return os.Getenv("D_EYES_AGENT_ID")
}

func (s *streamWriter) agentName() string {
	if strings.TrimSpace(s.cfg.AgentName) != "" {
		return s.cfg.AgentName
	}
	if env := strings.TrimSpace(os.Getenv("D_EYES_AGENT_NAME")); env != "" {
		return env
	}
	if host, err := os.Hostname(); err == nil {
		return host
	}
	return ""
}

func cloneEvent(evt *SystemEvent) *SystemEvent {
	if evt == nil {
		return nil
	}
	cp := *evt
	if evt.Metadata != nil {
		cp.Metadata = make(map[string]string, len(evt.Metadata))
		for k, v := range evt.Metadata {
			cp.Metadata[k] = v
		}
	}
	if evt.Payload != nil {
		cp.Payload = make(map[string]any, len(evt.Payload))
		for k, v := range evt.Payload {
			cp.Payload[k] = v
		}
	}
	if evt.Tags != nil {
		cp.Tags = make(map[string]string, len(evt.Tags))
		for k, v := range evt.Tags {
			cp.Tags[k] = v
		}
	}
	if evt.Raw != nil {
		cp.Raw = make(map[string]interface{}, len(evt.Raw))
		for k, v := range evt.Raw {
			cp.Raw[k] = v
		}
	}
	return &cp
}
