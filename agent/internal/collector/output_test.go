package collector

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

func TestBuildOutputHandler_StreamMode(t *testing.T) {
	t.Parallel()
	payloadCh := make(chan []byte, 1)
	prevFactory := newStreamHTTPClient
	newStreamHTTPClient = func() httpClient {
		return &stubHTTPClient{payloadCh: payloadCh}
	}
	defer func() { newStreamHTTPClient = prevFactory }()

	cfg := Config{
		Name: "stream-test",
		Output: Output{
			Mode: "stream",
			Stream: CollectorStreamConfig{
				URL:           "https://stream.local/api/v1/events",
				APIKey:        "token",
				AgentID:       "agent-100",
				AgentName:     "edge-100",
				MaxBatch:      1,
				FlushInterval: 5 * time.Millisecond,
			},
		},
	}
	var baseCount atomic.Int32
	base := EventHandlerFunc(func(context.Context, *SystemEvent) error {
		baseCount.Add(1)
		return nil
	})
	handler, cleanup, err := buildOutputHandler(cfg, base, nil)
	if err != nil {
		t.Fatalf("buildOutputHandler returned error: %v", err)
	}
	defer func() {
		if cleanup != nil {
			cleanup()
		}
	}()

	event := &SystemEvent{
		Timestamp: time.Now(),
		EventType: "unit_test",
		Source:    "test",
	}
	if err := handler.HandleEvent(context.Background(), event); err != nil {
		t.Fatalf("HandleEvent error: %v", err)
	}

	select {
	case body := <-payloadCh:
		verifyStreamPayload(t, body)
	case <-time.After(time.Second):
		t.Fatal("stream upload not received")
	}
	if baseCount.Load() != 1 {
		t.Fatalf("expected base handler to run once, got %d", baseCount.Load())
	}
}

func verifyStreamPayload(t *testing.T, data []byte) {
	t.Helper()
	var payload struct {
		AgentID   string            `json:"agent_id"`
		AgentName string            `json:"agent_name"`
		Metadata  map[string]string `json:"metadata"`
		Events    []json.RawMessage `json:"events"`
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatalf("invalid payload: %v", err)
	}
	if payload.AgentID != "agent-100" {
		t.Fatalf("unexpected agent id: %q", payload.AgentID)
	}
	if payload.AgentName != "edge-100" {
		t.Fatalf("unexpected agent name: %q", payload.AgentName)
	}
	if len(payload.Events) != 1 {
		t.Fatalf("unexpected event count: %d", len(payload.Events))
	}
	if payload.Metadata["source"] != "collector.stream" {
		t.Fatalf("metadata missing stream source: %+v", payload.Metadata)
	}
}

type stubHTTPClient struct {
	payloadCh chan<- []byte
}

func (c *stubHTTPClient) Do(req *http.Request) (*http.Response, error) {
	defer req.Body.Close()
	data, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}
	select {
	case c.payloadCh <- append([]byte(nil), data...):
	default:
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(bytes.NewReader(nil)),
		Header:     make(http.Header),
	}, nil
}
