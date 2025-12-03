package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/m-sec-org/d-eyes/agent/internal/agent/eventstream"
	"github.com/m-sec-org/d-eyes/agent/pkg/config"
)

type eventUploader struct {
	pipeline  *eventstream.Pipeline
	client    *http.Client
	endpoint  string
	apiKey    string
	agentID   string
	agentName string
}

type ingestRequest struct {
	AgentID   string          `json:"agent_id"`
	AgentName string          `json:"agent_name"`
	Events    json.RawMessage `json:"events"`
}

func newEventUploader(pipeline *eventstream.Pipeline, cfg config.RemoteConfig, agentID, agentName string) *eventUploader {
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
	}
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
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("server rejected events: %s %s", resp.Status, strings.TrimSpace(string(data)))
	}
	return nil
}
