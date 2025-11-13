package threatintel

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/m-sec-org/d-eyes/server/internal/model"
)

type metaDefenderProvider struct {
	baseURL string
	apiKey  string
	client  httpDoer
}

func newMetaDefenderProvider(baseURL, apiKey string, timeout time.Duration) *metaDefenderProvider {
	if baseURL == "" {
		baseURL = "https://api.metadefender.com/v4"
	}
	return &metaDefenderProvider{
		baseURL: strings.TrimRight(baseURL, "/"),
		apiKey:  strings.TrimSpace(apiKey),
		client:  newHTTPClient(timeout),
	}
}

func (p *metaDefenderProvider) Source() model.ThreatIntelSource {
	return model.ThreatIntelSourceMetaDefender
}

func (p *metaDefenderProvider) Process(ctx context.Context, req ProviderRequest) ([]*model.ThreatIntelVerdict, error) {
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
		return nil, fmt.Errorf("metadefender: missing indicator")
	}
	body, err := p.lookupHash(ctx, indicator)
	if err != nil {
		return nil, err
	}
	classification, confidence := parseMetaDefenderVerdict(body)
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
			"provider": "metadefender",
		}),
	}
	return []*model.ThreatIntelVerdict{verdict}, nil
}

func (p *metaDefenderProvider) lookupHash(ctx context.Context, hash string) ([]byte, error) {
	url := fmt.Sprintf("%s/hash/%s", p.baseURL, hash)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("metadefender: build request: %w", err)
	}
	if p.apiKey != "" {
		req.Header.Set("apikey", p.apiKey)
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("metadefender: http request: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("metadefender: read response: %w", err)
	}
	switch resp.StatusCode {
	case http.StatusOK:
		return body, nil
	case http.StatusNotFound:
		return body, nil
	case http.StatusTooManyRequests:
		return nil, &RetryableError{
			Err:        fmt.Errorf("metadefender: rate limited"),
			RetryAfter: parseRetryAfter(resp.Header.Get("Retry-After")),
		}
	default:
		if resp.StatusCode >= 500 {
			return nil, &RetryableError{
				Err:        fmt.Errorf("metadefender: remote error %s", resp.Status),
				RetryAfter: 30 * time.Second,
			}
		}
		return nil, fmt.Errorf("metadefender: unexpected status %s (%s)", resp.Status, strings.TrimSpace(string(body)))
	}
}

func (p *metaDefenderProvider) scanSample(ctx context.Context, req ProviderRequest) ([]*model.ThreatIntelVerdict, error) {
	artifact := req.Artifacts[0]
	if len(artifact.Blob) == 0 {
		return nil, fmt.Errorf("metadefender: artifact empty")
	}
	uploadResp, err := p.uploadArtifact(ctx, artifact.Blob)
	if err != nil {
		return nil, err
	}
	result, err := p.pollScanResult(ctx, uploadResp.DataID)
	if err != nil {
		return nil, err
	}
	indicator := req.Job.Indicator
	if indicator == "" {
		indicator = uploadResp.SHA256
	}
	classification, confidence := parseMetaDefenderVerdict(result)
	verdict := &model.ThreatIntelVerdict{
		Indicator:      indicator,
		Kind:           req.Job.Kind,
		Source:         p.Source(),
		Classification: classification,
		Confidence:     confidence,
		Raw:            result,
		RetrievedAt:    time.Now().UTC(),
		JobID:          req.Job.ID,
		TaskRunID:      req.Job.TaskRunID,
		Metadata: mergeMetadata(req.Job.Metadata, map[string]string{
			"provider": "metadefender",
			"mode":     "file_scan",
			"data_id":  uploadResp.DataID,
		}),
	}
	return []*model.ThreatIntelVerdict{verdict}, nil
}

type mdUploadResponse struct {
	DataID string `json:"data_id"`
	SHA256 string `json:"sha256"`
}

func (p *metaDefenderProvider) uploadArtifact(ctx context.Context, data []byte) (mdUploadResponse, error) {
	url := fmt.Sprintf("%s/file", p.baseURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		return mdUploadResponse{}, fmt.Errorf("metadefender: build upload request: %w", err)
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	if p.apiKey != "" {
		req.Header.Set("apikey", p.apiKey)
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return mdUploadResponse{}, fmt.Errorf("metadefender: upload request: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return mdUploadResponse{}, fmt.Errorf("metadefender: read upload response: %w", err)
	}
	switch resp.StatusCode {
	case http.StatusOK:
		var upload mdUploadResponse
		if err := json.Unmarshal(body, &upload); err != nil {
			return mdUploadResponse{}, fmt.Errorf("metadefender: decode upload: %w", err)
		}
		return upload, nil
	case http.StatusTooManyRequests:
		return mdUploadResponse{}, &RetryableError{Err: fmt.Errorf("metadefender: rate limited"), RetryAfter: parseRetryAfter(resp.Header.Get("Retry-After"))}
	default:
		if resp.StatusCode >= 500 {
			return mdUploadResponse{}, &RetryableError{Err: fmt.Errorf("metadefender: remote error %s", resp.Status), RetryAfter: 30 * time.Second}
		}
		return mdUploadResponse{}, fmt.Errorf("metadefender: upload failed %s (%s)", resp.Status, strings.TrimSpace(string(body)))
	}
}

func (p *metaDefenderProvider) pollScanResult(ctx context.Context, dataID string) ([]byte, error) {
	if strings.TrimSpace(dataID) == "" {
		return nil, fmt.Errorf("metadefender: empty data id")
	}
	url := fmt.Sprintf("%s/file/%s", p.baseURL, dataID)
	const maxAttempts = 15
	for attempt := 0; attempt < maxAttempts; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, fmt.Errorf("metadefender: build poll request: %w", err)
		}
		if p.apiKey != "" {
			req.Header.Set("apikey", p.apiKey)
		}
		resp, err := p.client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("metadefender: poll request: %w", err)
		}
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 5<<20))
		resp.Body.Close()
		if readErr != nil {
			return nil, fmt.Errorf("metadefender: read poll response: %w", readErr)
		}
		switch resp.StatusCode {
		case http.StatusOK:
			if isCompleted(body) {
				return body, nil
			}
		case http.StatusTooManyRequests:
			return nil, &RetryableError{Err: fmt.Errorf("metadefender: rate limited"), RetryAfter: parseRetryAfter(resp.Header.Get("Retry-After"))}
		default:
			if resp.StatusCode >= 500 {
				return nil, &RetryableError{Err: fmt.Errorf("metadefender: remote error %s", resp.Status), RetryAfter: 30 * time.Second}
			}
			return nil, fmt.Errorf("metadefender: poll failed %s (%s)", resp.Status, strings.TrimSpace(string(body)))
		}
		time.Sleep(2 * time.Second)
	}
	return nil, fmt.Errorf("metadefender: poll timeout")
}

func isCompleted(body []byte) bool {
	var parsed struct {
		ScanResults struct {
			Progress int `json:"progress_percentage"`
		} `json:"scan_results"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return true
	}
	return parsed.ScanResults.Progress >= 100
}

func parseMetaDefenderVerdict(body []byte) (classification, confidence string) {
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		return "", ""
	}
	if scan, ok := payload["scan_results"].(map[string]any); ok {
		classification = pickString(scan, "scan_all_result_a", "threat_name")
		confidence = pickString(scan, "scan_all_result_i", "confidence")
	}
	if classification == "" {
		classification = pickString(payload, "threat", "result")
	}
	return classification, confidence
}
