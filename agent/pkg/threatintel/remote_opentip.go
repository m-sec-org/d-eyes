package threatintel

import (
	"context"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type openTIPRemote struct {
	baseURL string
	apiKey  string
	client  *http.Client
	timeout time.Duration
}

func newOpenTIPRemote(cfg Config) *openTIPRemote {
	baseURL := cfg.OpenTIPBaseURL
	if baseURL == "" {
		baseURL = DefaultOpenTIPBaseURL
	}
	timeout := cfg.HTTPTimeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	return &openTIPRemote{
		baseURL: strings.TrimRight(strings.TrimSpace(baseURL), "/"),
		apiKey:  strings.TrimSpace(cfg.OpenTIPAPIKey),
		client:  &http.Client{Timeout: timeout},
		timeout: timeout,
	}
}

func (p *openTIPRemote) Name() string {
	return "opentip"
}

func (p *openTIPRemote) LookupHash(ctx context.Context, sha256 string) (remoteVerdict, error) {
	endpoint, err := url.Parse(p.baseURL + "/search/hash")
	if err != nil {
		return remoteVerdict{}, &remoteError{Provider: p.Name(), Kind: remoteErrorKindPermanent}
	}
	q := endpoint.Query()
	q.Set("request", sha256)
	endpoint.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return remoteVerdict{}, &remoteError{Provider: p.Name(), Kind: remoteErrorKindPermanent}
	}
	if p.apiKey != "" {
		req.Header.Set("x-api-key", p.apiKey)
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
		classification, confidence := parseOpenTIPVerdict(body)
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

func (p *openTIPRemote) ScanFile(ctx context.Context, path string, filename string) (remoteVerdict, error) {
	if strings.TrimSpace(path) == "" {
		return remoteVerdict{}, &remoteError{Provider: p.Name(), Kind: remoteErrorKindPermanent}
	}
	endpoint, err := url.Parse(p.baseURL + "/scan/file")
	if err != nil {
		return remoteVerdict{}, &remoteError{Provider: p.Name(), Kind: remoteErrorKindPermanent}
	}
	if filename == "" {
		filename = filepath.Base(path)
	}
	if filename != "" {
		q := endpoint.Query()
		q.Set("filename", filename)
		endpoint.RawQuery = q.Encode()
	}
	file, err := os.Open(path)
	if err != nil {
		return remoteVerdict{}, err
	}
	defer file.Close()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), file)
	if err != nil {
		return remoteVerdict{}, &remoteError{Provider: p.Name(), Kind: remoteErrorKindPermanent}
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	if p.apiKey != "" {
		req.Header.Set("x-api-key", p.apiKey)
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return remoteVerdict{}, &remoteError{Provider: p.Name(), Kind: remoteErrorKindTemporary}
	}
	body, readErr := readResponseBody(resp, 5<<20)
	if readErr != nil {
		return remoteVerdict{}, &remoteError{Provider: p.Name(), Kind: remoteErrorKindTemporary}
	}
	ttl := parseCacheTTL(resp.Header)
	status := resp.StatusCode
	switch status {
	case http.StatusOK, http.StatusAccepted:
		classification, confidence := parseOpenTIPVerdict(body)
		return remoteVerdict{
			Classification: classification,
			Confidence:     confidence,
			Raw:            body,
			TTL:            ttl,
			StatusCode:     status,
			Mode:           "file_scan",
		}, nil
	case http.StatusTooManyRequests:
		return remoteVerdict{}, &remoteError{Provider: p.Name(), Kind: remoteErrorKindRateLimit, StatusCode: status, RetryAfter: parseRetryAfter(resp.Header.Get("Retry-After"))}
	default:
		if status >= 500 {
			return remoteVerdict{}, &remoteError{Provider: p.Name(), Kind: remoteErrorKindTemporary, StatusCode: status, RetryAfter: 30 * time.Second}
		}
		return remoteVerdict{}, &remoteError{Provider: p.Name(), Kind: remoteErrorKindPermanent, StatusCode: status}
	}
}

func parseOpenTIPVerdict(body []byte) (classification, confidence string) {
	payload := parseJSON(body)
	if payload == nil {
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
