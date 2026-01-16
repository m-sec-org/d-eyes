package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/m-sec-org/d-eyes/agent/internal/agent/eventstream"
	"github.com/m-sec-org/d-eyes/agent/internal/agent/remotelog"
	"github.com/m-sec-org/d-eyes/agent/pkg/config"
)

type eventUploader struct {
	pipeline  *eventstream.Pipeline
	client    *http.Client
	endpoint  string
	apiKey    string
	agentID   string
	agentName string
	debugLog  *remotelog.Logger
}

type ingestRequest struct {
	AgentID   string          `json:"agent_id"`
	AgentName string          `json:"agent_name"`
	Events    json.RawMessage `json:"events"`
}

func newEventUploader(pipeline *eventstream.Pipeline, cfg config.RemoteConfig, agentID, agentName string, debugLog *remotelog.Logger) *eventUploader {
	base := strings.TrimRight(cfg.ServerAPIBase, "/")
	if pipeline == nil || base == "" || agentID == "" {
		return nil
	}
	return &eventUploader{
		pipeline:  pipeline,
		client:    &http.Client{Timeout: 15 * time.Second},
		endpoint:  base + "/api/v1/events/ingest",
		apiKey:    cfg.AgentToken,
		agentID:   agentID,
		agentName: agentName,
		debugLog:  debugLog,
	}
}

func (u *eventUploader) debug(event string, fields ...remotelog.Field) {
	if u == nil || u.debugLog == nil {
		return
	}
	u.debugLog.Debug(event, fields...)
}

func (u *eventUploader) run(ctx context.Context) {
	if u == nil {
		return
	}
	backoff := time.Second
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		batch, count := u.pipeline.NextJSONBatch()
		if count == 0 {
			select {
			case <-ctx.Done():
				return
			case <-time.After(200 * time.Millisecond):
			}
			continue
		}
		if err := u.uploadBatch(ctx, batch); err != nil {
			log.Printf("[remote] event upload failed: %v", err)
			u.pipeline.RequeueBatch(batch)
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			if backoff < 10*time.Second {
				backoff *= 2
			}
			continue
		}
		backoff = time.Second
	}
}

func (u *eventUploader) uploadBatch(ctx context.Context, batch []byte) error {
	method := http.MethodPost
	path := safeURLPath(u.endpoint)
	u.debug("http.events.ingest",
		remotelog.Field{Key: "phase", Value: "start"},
		remotelog.Field{Key: "method", Value: method},
		remotelog.Field{Key: "path", Value: path},
	)
	start := time.Now()
	payload := ingestRequest{
		AgentID:   u.agentID,
		AgentName: u.agentName,
		Events:    batch,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if strings.TrimSpace(u.apiKey) != "" {
		req.Header.Set("X-API-Key", u.apiKey)
	}
	resp, err := u.client.Do(req)
	if err != nil {
		err = sanitizeHTTPError(err)
		u.debug("http.events.ingest",
			remotelog.Field{Key: "phase", Value: "error"},
			remotelog.Field{Key: "method", Value: method},
			remotelog.Field{Key: "path", Value: path},
			remotelog.Field{Key: "dur_ms", Value: time.Since(start).Milliseconds()},
			remotelog.Field{Key: "err", Value: err},
		)
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		err := fmt.Errorf("server rejected events: %s %s", resp.Status, strings.TrimSpace(string(data)))
		u.debug("http.events.ingest",
			remotelog.Field{Key: "phase", Value: "error"},
			remotelog.Field{Key: "method", Value: method},
			remotelog.Field{Key: "path", Value: path},
			remotelog.Field{Key: "status", Value: resp.StatusCode},
			remotelog.Field{Key: "dur_ms", Value: time.Since(start).Milliseconds()},
			remotelog.Field{Key: "err", Value: err},
		)
		return err
	}
	u.debug("http.events.ingest",
		remotelog.Field{Key: "phase", Value: "done"},
		remotelog.Field{Key: "method", Value: method},
		remotelog.Field{Key: "path", Value: path},
		remotelog.Field{Key: "status", Value: resp.StatusCode},
		remotelog.Field{Key: "dur_ms", Value: time.Since(start).Milliseconds()},
	)
	return nil
}

func safeURLPath(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	parsed, err := url.Parse(raw)
	if err == nil && parsed != nil {
		if parsed.Path != "" {
			return truncatePath(parsed.Path, 256)
		}
		return "/"
	}
	if idx := strings.IndexByte(raw, '?'); idx >= 0 {
		raw = raw[:idx]
	}
	if idx := strings.IndexByte(raw, '#'); idx >= 0 {
		raw = raw[:idx]
	}
	return truncatePath(raw, 256)
}

func truncatePath(path string, max int) string {
	if max <= 0 || len(path) <= max {
		return path
	}
	if max == 1 {
		return path[:1]
	}
	return path[:max-1] + "…"
}

func sanitizeHTTPError(err error) error {
	var urlErr *url.Error
	if err == nil || !errors.As(err, &urlErr) || urlErr == nil {
		return err
	}
	safeURL := safeURLPath(urlErr.URL)
	if safeURL == "" {
		return urlErr.Err
	}
	return fmt.Errorf("%s %s: %v", urlErr.Op, safeURL, urlErr.Err)
}
