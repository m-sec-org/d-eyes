package threatintel

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/m-sec-org/d-eyes/server/internal/model"
)

type openTIPProvider struct {
	baseURL string
	apiKey  string
	client  httpDoer
}

func newOpenTIPProvider(baseURL, apiKey string, timeout time.Duration) *openTIPProvider {
	if baseURL == "" {
		baseURL = "https://opentip.kaspersky.com/api/v1"
	}
	return &openTIPProvider{
		baseURL: strings.TrimRight(baseURL, "/"),
		apiKey:  strings.TrimSpace(apiKey),
		client:  newHTTPClient(timeout),
	}
}

func (p *openTIPProvider) Source() model.ThreatIntelSource {
	return model.ThreatIntelSourceOpenTIP
}

func (p *openTIPProvider) Process(ctx context.Context, req ProviderRequest) ([]*model.ThreatIntelVerdict, error) {
	if req.Sample != nil && len(req.Artifacts) > 0 {
		if verdicts, err := p.scanSample(ctx, req); err == nil {
			return verdicts, nil
		} else if !isNotFound(err) {
			return nil, err
		}
	}
	indicator := strings.TrimSpace(req.Job.Indicator)
	if indicator == "" && req.Sample != nil {
		indicator = strings.TrimSpace(req.Sample.Hash)
	}
	if indicator == "" {
		return nil, fmt.Errorf("opentip: missing indicator")
	}
	body, err := p.lookupHash(ctx, indicator)
	if err != nil {
		return nil, err
	}
	classification, confidence := parseOpenTIPVerdict(body)
	verdict := &model.ThreatIntelVerdict{
		Indicator:      indicator,
		Kind:           req.Job.Kind,
		Source:         p.Source(),
		Classification: classification,
		Confidence:     confidence,
		Raw:            body,
		RetrievedAt:    time.Now().UTC(),
		JobID:          req.Job.ID,
		TaskRunID:      req.Job.TaskRunID,
		Metadata: mergeMetadata(req.Job.Metadata, map[string]string{
			"provider": "opentip",
			"mode":     "hash_lookup",
		}),
	}
	return []*model.ThreatIntelVerdict{verdict}, nil
}

func (p *openTIPProvider) scanSample(ctx context.Context, req ProviderRequest) ([]*model.ThreatIntelVerdict, error) {
	artifact := req.Artifacts[0]
	if len(artifact.Blob) == 0 {
		return nil, fmt.Errorf("opentip: artifact empty")
	}
	endpoint, err := url.Parse(p.baseURL + "/scan/file")
	if err != nil {
		return nil, fmt.Errorf("opentip: parse scan url: %w", err)
	}
	if name := preferredFilename(req.Sample, artifact); name != "" {
		q := endpoint.Query()
		q.Set("filename", name)
		endpoint.RawQuery = q.Encode()
	}
	body := bytes.NewReader(artifact.Blob)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), body)
	if err != nil {
		return nil, fmt.Errorf("opentip: build scan request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/octet-stream")
	if p.apiKey != "" {
		httpReq.Header.Set("x-api-key", p.apiKey)
	}
	resp, err := p.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("opentip: scan request: %w", err)
	}
	defer resp.Body.Close()
	payload, err := io.ReadAll(io.LimitReader(resp.Body, 5<<20))
	if err != nil {
		return nil, fmt.Errorf("opentip: read scan response: %w", err)
	}
	switch resp.StatusCode {
	case http.StatusOK, http.StatusAccepted:
		classification, confidence := parseOpenTIPVerdict(payload)
		indicator := req.Job.Indicator
		if indicator == "" && req.Sample != nil {
			indicator = req.Sample.Hash
		}
		verdict := &model.ThreatIntelVerdict{
			Indicator:      indicator,
			Kind:           req.Job.Kind,
			Source:         p.Source(),
			Classification: classification,
			Confidence:     confidence,
			Raw:            payload,
			RetrievedAt:    time.Now().UTC(),
			JobID:          req.Job.ID,
			TaskRunID:      req.Job.TaskRunID,
			Metadata: mergeMetadata(req.Job.Metadata, map[string]string{
				"provider": "opentip",
				"mode":     "file_scan",
			}),
		}
		return []*model.ThreatIntelVerdict{verdict}, nil
	case http.StatusTooManyRequests:
		return nil, &RetryableError{Err: fmt.Errorf("opentip: rate limited"), RetryAfter: parseRetryAfter(resp.Header.Get("Retry-After"))}
	default:
		if resp.StatusCode >= 500 {
			return nil, &RetryableError{Err: fmt.Errorf("opentip: remote error %s", resp.Status), RetryAfter: 30 * time.Second}
		}
		return nil, fmt.Errorf("opentip: scan failed %s (%s)", resp.Status, strings.TrimSpace(string(payload)))
	}
}

func (p *openTIPProvider) lookupHash(ctx context.Context, hash string) ([]byte, error) {
	u, err := url.Parse(p.baseURL + "/search/hash")
	if err != nil {
		return nil, fmt.Errorf("opentip: parse base url: %w", err)
	}
	q := u.Query()
	q.Set("request", hash)
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("opentip: build request: %w", err)
	}
	if p.apiKey != "" {
		req.Header.Set("x-api-key", p.apiKey)
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("opentip: http request: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("opentip: read response: %w", err)
	}
	switch resp.StatusCode {
	case http.StatusOK:
		return body, nil
	case http.StatusNotFound:
		return body, nil
	case http.StatusTooManyRequests:
		retryAfter := parseRetryAfter(resp.Header.Get("Retry-After"))
		return nil, &RetryableError{
			Err:        fmt.Errorf("opentip: rate limited"),
			RetryAfter: retryAfter,
		}
	default:
		if resp.StatusCode >= 500 {
			return nil, &RetryableError{
				Err:        fmt.Errorf("opentip: remote error %s", resp.Status),
				RetryAfter: 30 * time.Second,
			}
		}
		return nil, fmt.Errorf("opentip: unexpected status %s (%s)", resp.Status, strings.TrimSpace(string(body)))
	}
}

func parseOpenTIPVerdict(body []byte) (classification, confidence string) {
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		return "", ""
	}
	classification = pickString(payload, "verdict", "verdictName", "threatName", "result")
	confidence = pickString(payload, "confidence", "score")
	if classification == "" {
		if data, ok := payload["data"].([]any); ok {
			for _, item := range data {
				if m, ok := item.(map[string]any); ok {
					classification = pickString(m, "verdict", "verdictName", "detectionName")
					if classification != "" {
						confidence = pickString(m, "confidence", "probability")
						break
					}
				}
			}
		}
	}
	return classification, confidence
}

func preferredFilename(sample *model.ThreatIntelSample, artifact model.Artifact) string {
	if artifact.Name != "" {
		return artifact.Name
	}
	if sample != nil && sample.Filename != "" {
		return sample.Filename
	}
	if sample != nil && sample.Hash != "" {
		return sample.Hash
	}
	return "sample.bin"
}

func isNotFound(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(strings.ToLower(err.Error()), "not found")
}
