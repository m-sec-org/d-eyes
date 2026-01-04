package threatintel

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type remoteProvider interface {
	Name() string
	LookupHash(ctx context.Context, sha256 string) (remoteVerdict, error)
	ScanFile(ctx context.Context, path string, filename string) (remoteVerdict, error)
}

type remoteVerdict struct {
	Classification string
	Confidence     string
	Raw            []byte
	TTL            time.Duration
	StatusCode     int
	Mode           string
	NotFound       bool
}

type remoteErrorKind string

const (
	remoteErrorKindRateLimit remoteErrorKind = "rate_limit"
	remoteErrorKindTemporary remoteErrorKind = "temporary"
	remoteErrorKindPermanent remoteErrorKind = "permanent"
)

type remoteError struct {
	Provider   string
	Kind       remoteErrorKind
	StatusCode int
	RetryAfter time.Duration
}

func (e *remoteError) Error() string {
	if e == nil {
		return "<nil>"
	}
	if e.StatusCode > 0 {
		return fmt.Sprintf("%s remote error (%s, status=%d)", e.Provider, e.Kind, e.StatusCode)
	}
	return fmt.Sprintf("%s remote error (%s)", e.Provider, e.Kind)
}

func parseRetryAfter(header string) time.Duration {
	header = strings.TrimSpace(header)
	if header == "" {
		return 30 * time.Second
	}
	if seconds, err := strconv.Atoi(header); err == nil && seconds > 0 {
		return time.Duration(seconds) * time.Second
	}
	if d, err := time.ParseDuration(header); err == nil && d > 0 {
		return d
	}
	if t, err := http.ParseTime(header); err == nil {
		d := time.Until(t)
		if d > 0 {
			return d
		}
	}
	return 30 * time.Second
}

func pickString(m map[string]any, keys ...string) string {
	for _, key := range keys {
		if v, ok := m[key]; ok {
			if s, ok := v.(string); ok && strings.TrimSpace(s) != "" {
				return s
			}
		}
		if v, ok := m[strings.ToLower(key)]; ok {
			if s, ok := v.(string); ok && strings.TrimSpace(s) != "" {
				return s
			}
		}
	}
	return ""
}

func parseCacheTTL(headers http.Header) time.Duration {
	raw := strings.TrimSpace(headers.Get("Cache-Control"))
	if raw != "" {
		parts := strings.Split(raw, ",")
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if strings.HasPrefix(part, "max-age=") {
				if seconds, err := strconv.Atoi(strings.TrimPrefix(part, "max-age=")); err == nil && seconds > 0 {
					return time.Duration(seconds) * time.Second
				}
			}
		}
	}
	if raw := strings.TrimSpace(headers.Get("Expires")); raw != "" {
		if t, err := http.ParseTime(raw); err == nil {
			d := time.Until(t)
			if d > 0 {
				return d
			}
		}
	}
	return 0
}

func readResponseBody(resp *http.Response, limit int64) ([]byte, error) {
	if resp == nil || resp.Body == nil {
		return nil, nil
	}
	defer resp.Body.Close()
	if limit <= 0 {
		limit = 1 << 20
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit))
	if err != nil {
		return nil, err
	}
	return body, nil
}

func parseJSON(body []byte) map[string]any {
	if len(body) == 0 {
		return nil
	}
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil
	}
	return payload
}

func joinURL(base string, path string) (string, error) {
	u, err := url.Parse(strings.TrimRight(strings.TrimSpace(base), "/"))
	if err != nil {
		return "", err
	}
	u.Path = strings.TrimRight(u.Path, "/") + path
	return u.String(), nil
}
