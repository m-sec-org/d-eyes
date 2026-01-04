package threatintel

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

type metaDefenderRemote struct {
	baseURL string
	apiKey  string
	client  *http.Client
	timeout time.Duration
}

func newMetaDefenderRemote(cfg Config) *metaDefenderRemote {
	baseURL := cfg.MetaDefenderBaseURL
	if baseURL == "" {
		baseURL = DefaultMetaDefenderBaseURL
	}
	timeout := cfg.HTTPTimeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	return &metaDefenderRemote{
		baseURL: strings.TrimRight(strings.TrimSpace(baseURL), "/"),
		apiKey:  strings.TrimSpace(cfg.MetaDefenderAPIKey),
		client:  &http.Client{Timeout: timeout},
		timeout: timeout,
	}
}

func (p *metaDefenderRemote) Name() string {
	return "metadefender"
}

func (p *metaDefenderRemote) LookupHash(ctx context.Context, sha256 string) (remoteVerdict, error) {
	endpoint, err := joinURL(p.baseURL, "/hash/"+sha256)
	if err != nil {
		return remoteVerdict{}, &remoteError{Provider: p.Name(), Kind: remoteErrorKindPermanent}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return remoteVerdict{}, &remoteError{Provider: p.Name(), Kind: remoteErrorKindPermanent}
	}
	if p.apiKey != "" {
		req.Header.Set("apikey", p.apiKey)
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return remoteVerdict{}, &remoteError{Provider: p.Name(), Kind: remoteErrorKindTemporary}
	}
	body, readErr := readResponseBody(resp, 1<<20)
	if readErr != nil {
		return remoteVerdict{}, &remoteError{Provider: p.Name(), Kind: remoteErrorKindTemporary}
	}
	ttl := parseCacheTTL(resp.Header)
	status := resp.StatusCode
	switch status {
	case http.StatusOK:
		classification, confidence := parseMetaDefenderVerdict(body)
		return remoteVerdict{
			Classification: classification,
			Confidence:     confidence,
			Raw:            body,
			TTL:            ttl,
			StatusCode:     status,
			Mode:           "hash_lookup",
		}, nil
	case http.StatusNotFound:
		return remoteVerdict{Raw: body, TTL: ttl, StatusCode: status, Mode: "hash_lookup", NotFound: true}, nil
	case http.StatusTooManyRequests:
		return remoteVerdict{}, &remoteError{Provider: p.Name(), Kind: remoteErrorKindRateLimit, StatusCode: status, RetryAfter: parseRetryAfter(resp.Header.Get("Retry-After"))}
	default:
		if status >= 500 {
			return remoteVerdict{}, &remoteError{Provider: p.Name(), Kind: remoteErrorKindTemporary, StatusCode: status, RetryAfter: 30 * time.Second}
		}
		return remoteVerdict{}, &remoteError{Provider: p.Name(), Kind: remoteErrorKindPermanent, StatusCode: status}
	}
}

func (p *metaDefenderRemote) ScanFile(ctx context.Context, path string, filename string) (remoteVerdict, error) {
	dataID, _, ttl, status, err := p.upload(ctx, path)
	if err != nil {
		return remoteVerdict{}, err
	}
	body, ttlPoll, statusPoll, err := p.poll(ctx, dataID)
	if err != nil {
		return remoteVerdict{}, err
	}
	if ttlPoll > 0 {
		ttl = ttlPoll
	}
	if statusPoll > 0 {
		status = statusPoll
	}
	classification, confidence := parseMetaDefenderVerdict(body)
	return remoteVerdict{
		Classification: classification,
		Confidence:     confidence,
		Raw:            body,
		TTL:            ttl,
		StatusCode:     status,
		Mode:           "file_scan",
		NotFound:       false,
	}, nil
}

type mdUploadResponse struct {
	DataID string `json:"data_id"`
	SHA256 string `json:"sha256"`
}

func (p *metaDefenderRemote) upload(ctx context.Context, path string) (dataID string, sha256 string, ttl time.Duration, status int, err error) {
	if strings.TrimSpace(path) == "" {
		return "", "", 0, 0, &remoteError{Provider: p.Name(), Kind: remoteErrorKindPermanent}
	}
	endpoint, urlErr := joinURL(p.baseURL, "/file")
	if urlErr != nil {
		return "", "", 0, 0, &remoteError{Provider: p.Name(), Kind: remoteErrorKindPermanent}
	}
	file, openErr := os.Open(path)
	if openErr != nil {
		return "", "", 0, 0, openErr
	}
	defer file.Close()

	req, reqErr := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, file)
	if reqErr != nil {
		return "", "", 0, 0, &remoteError{Provider: p.Name(), Kind: remoteErrorKindPermanent}
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	if p.apiKey != "" {
		req.Header.Set("apikey", p.apiKey)
	}
	resp, doErr := p.client.Do(req)
	if doErr != nil {
		return "", "", 0, 0, &remoteError{Provider: p.Name(), Kind: remoteErrorKindTemporary}
	}
	body, readErr := readResponseBody(resp, 2<<20)
	if readErr != nil {
		return "", "", 0, 0, &remoteError{Provider: p.Name(), Kind: remoteErrorKindTemporary}
	}
	ttl = parseCacheTTL(resp.Header)
	status = resp.StatusCode
	switch status {
	case http.StatusOK:
		var upload mdUploadResponse
		if err := json.Unmarshal(body, &upload); err != nil {
			return "", "", 0, 0, &remoteError{Provider: p.Name(), Kind: remoteErrorKindTemporary, StatusCode: status}
		}
		if strings.TrimSpace(upload.DataID) == "" {
			return "", "", 0, 0, &remoteError{Provider: p.Name(), Kind: remoteErrorKindTemporary, StatusCode: status}
		}
		return upload.DataID, strings.TrimSpace(upload.SHA256), ttl, status, nil
	case http.StatusTooManyRequests:
		return "", "", 0, 0, &remoteError{Provider: p.Name(), Kind: remoteErrorKindRateLimit, StatusCode: status, RetryAfter: parseRetryAfter(resp.Header.Get("Retry-After"))}
	default:
		if status >= 500 {
			return "", "", 0, 0, &remoteError{Provider: p.Name(), Kind: remoteErrorKindTemporary, StatusCode: status, RetryAfter: 30 * time.Second}
		}
		return "", "", 0, 0, &remoteError{Provider: p.Name(), Kind: remoteErrorKindPermanent, StatusCode: status}
	}
}

func (p *metaDefenderRemote) poll(ctx context.Context, dataID string) (body []byte, ttl time.Duration, status int, err error) {
	dataID = strings.TrimSpace(dataID)
	if dataID == "" {
		return nil, 0, 0, &remoteError{Provider: p.Name(), Kind: remoteErrorKindPermanent}
	}
	endpoint, urlErr := joinURL(p.baseURL, "/file/"+dataID)
	if urlErr != nil {
		return nil, 0, 0, &remoteError{Provider: p.Name(), Kind: remoteErrorKindPermanent}
	}
	const maxAttempts = 15
	for attempt := 0; attempt < maxAttempts; attempt++ {
		select {
		case <-ctx.Done():
			return nil, 0, 0, ctx.Err()
		default:
		}
		req, reqErr := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if reqErr != nil {
			return nil, 0, 0, &remoteError{Provider: p.Name(), Kind: remoteErrorKindPermanent}
		}
		if p.apiKey != "" {
			req.Header.Set("apikey", p.apiKey)
		}
		resp, doErr := p.client.Do(req)
		if doErr != nil {
			return nil, 0, 0, &remoteError{Provider: p.Name(), Kind: remoteErrorKindTemporary}
		}
		payload, readErr := readResponseBody(resp, 5<<20)
		if readErr != nil {
			return nil, 0, 0, &remoteError{Provider: p.Name(), Kind: remoteErrorKindTemporary}
		}
		ttl = parseCacheTTL(resp.Header)
		status = resp.StatusCode
		switch status {
		case http.StatusOK:
			if isMetaDefenderCompleted(payload) {
				return payload, ttl, status, nil
			}
		case http.StatusTooManyRequests:
			return nil, 0, 0, &remoteError{Provider: p.Name(), Kind: remoteErrorKindRateLimit, StatusCode: status, RetryAfter: parseRetryAfter(resp.Header.Get("Retry-After"))}
		default:
			if status >= 500 {
				return nil, 0, 0, &remoteError{Provider: p.Name(), Kind: remoteErrorKindTemporary, StatusCode: status, RetryAfter: 30 * time.Second}
			}
			return nil, 0, 0, &remoteError{Provider: p.Name(), Kind: remoteErrorKindPermanent, StatusCode: status}
		}
		select {
		case <-ctx.Done():
			return nil, 0, 0, ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
	return nil, 0, 0, fmt.Errorf("metadefender: poll timeout")
}

func isMetaDefenderCompleted(body []byte) bool {
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
	payload := parseJSON(body)
	if payload == nil {
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
