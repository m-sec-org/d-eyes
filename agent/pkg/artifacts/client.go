package artifacts

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/m-sec-org/d-eyes/agent/internal/agent/remotelog"
)

// Config 控制 Artifact Client 行为。
type Config struct {
	BaseURL    string
	APIKey     string
	Timeout    time.Duration
	RetryCount int
	RetryWait  time.Duration
	UserAgent  string
	HTTPClient *http.Client
	Debug      bool
}

// UploadInput 描述一次上传所需的信息。
type UploadInput struct {
	Path        string
	ContentType string
	Encryption  string
}

// UploadResult 返回成功上传后的引用信息。
type UploadResult struct {
	Token    string
	Hash     string
	Size     int64
	Filename string
}

// Client 负责与 Server Artifact API 通信。
type Client struct {
	baseURL    string
	apiKey     string
	userAgent  string
	httpClient *http.Client
	retryCount int
	retryWait  time.Duration
	timeout    time.Duration
	debugLog   *remotelog.Logger
}

const (
	defaultTimeout    = 30 * time.Second
	defaultRetryCount = 3
	defaultRetryWait  = time.Second
)

// NewClient 根据配置创建 Artifact Client。
func NewClient(cfg Config) (*Client, error) {
	base := strings.TrimSpace(cfg.BaseURL)
	if base == "" {
		return nil, fmt.Errorf("artifacts: base url is required")
	}
	if _, err := url.Parse(base); err != nil {
		return nil, fmt.Errorf("artifacts: invalid base url: %w", err)
	}
	apiKey := strings.TrimSpace(cfg.APIKey)
	if apiKey == "" {
		return nil, fmt.Errorf("artifacts: api key is required")
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	retryCount := cfg.RetryCount
	if retryCount <= 0 {
		retryCount = defaultRetryCount
	}
	retryWait := cfg.RetryWait
	if retryWait <= 0 {
		retryWait = defaultRetryWait
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: timeout}
	}
	ua := strings.TrimSpace(cfg.UserAgent)
	if ua == "" {
		ua = "d-eyes-agent"
	}
	var debugLog *remotelog.Logger
	if cfg.Debug {
		debugLog = remotelog.New(remotelog.Config{
			Enabled: true,
			Secrets: []string{apiKey},
		})
	}
	return &Client{
		baseURL:    strings.TrimRight(base, "/"),
		apiKey:     apiKey,
		userAgent:  ua,
		httpClient: client,
		retryCount: retryCount,
		retryWait:  retryWait,
		timeout:    timeout,
		debugLog:   debugLog,
	}, nil
}

// Upload 将文件上传到 Server，并返回可在 ReportResult metadata 中使用的 token。
func (c *Client) Upload(ctx context.Context, input UploadInput) (*UploadResult, error) {
	if c == nil {
		return nil, fmt.Errorf("artifacts: client is nil")
	}
	info, err := os.Stat(input.Path)
	if err != nil {
		return nil, fmt.Errorf("artifacts: stat file: %w", err)
	}
	if info.IsDir() {
		return nil, fmt.Errorf("artifacts: %s is a directory", input.Path)
	}
	hashHex, err := computeFileHash(input.Path)
	if err != nil {
		return nil, fmt.Errorf("artifacts: hash file: %w", err)
	}
	contentType := strings.TrimSpace(input.ContentType)
	if contentType == "" {
		contentType = mime.TypeByExtension(strings.ToLower(filepath.Ext(info.Name())))
	}
	if contentType == "" {
		contentType = "application/octet-stream"
	}

	enc := strings.TrimSpace(input.Encryption)
	if enc == "" {
		enc = "none"
	}

	reqBody := presignRequest{
		Filename:    info.Name(),
		ContentType: contentType,
		Hash:        hashHex,
		Size:        info.Size(),
		Encryption:  enc,
	}
	var presign presignResponse
	if err := c.doJSON(ctx, http.MethodPost, c.baseURL+"/api/v1/artifacts/presign", reqBody, &presign); err != nil {
		return nil, err
	}
	if err := c.uploadFile(ctx, presign.UploadURL, contentType, input.Path); err != nil {
		return nil, err
	}
	return &UploadResult{
		Token:    presign.UploadID,
		Hash:     hashHex,
		Size:     info.Size(),
		Filename: info.Name(),
	}, nil
}

func (c *Client) debug(event string, fields ...remotelog.Field) {
	if c == nil || c.debugLog == nil {
		return
	}
	c.debugLog.Debug(event, fields...)
}

func (c *Client) doJSON(ctx context.Context, method, endpoint string, payload any, out any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	path := safeURLPath(endpoint)
	var lastErr error
	for attempt := 0; attempt < c.retryCount; attempt++ {
		req, err := http.NewRequestWithContext(ctx, method, endpoint, bytes.NewReader(body))
		if err != nil {
			return err
		}
		c.applyHeaders(req)
		req.Header.Set("Content-Type", "application/json")
		start := time.Now()
		resp, err := c.httpClient.Do(req)
		if err != nil {
			lastErr = sanitizeHTTPError(err)
			c.debug("http.artifacts.presign",
				remotelog.Field{Key: "phase", Value: "error"},
				remotelog.Field{Key: "method", Value: method},
				remotelog.Field{Key: "path", Value: path},
				remotelog.Field{Key: "dur_ms", Value: time.Since(start).Milliseconds()},
				remotelog.Field{Key: "err", Value: lastErr},
			)
		} else {
			respBody, readErr := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode < 300 && readErr == nil {
				c.debug("http.artifacts.presign",
					remotelog.Field{Key: "phase", Value: "done"},
					remotelog.Field{Key: "method", Value: method},
					remotelog.Field{Key: "path", Value: path},
					remotelog.Field{Key: "status", Value: resp.StatusCode},
					remotelog.Field{Key: "dur_ms", Value: time.Since(start).Milliseconds()},
				)
				if out != nil {
					if err := json.Unmarshal(respBody, out); err != nil {
						return err
					}
				}
				return nil
			}
			if readErr != nil {
				lastErr = readErr
			} else {
				lastErr = fmt.Errorf("artifacts: request failed (%d): %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
			}
			c.debug("http.artifacts.presign",
				remotelog.Field{Key: "phase", Value: "error"},
				remotelog.Field{Key: "method", Value: method},
				remotelog.Field{Key: "path", Value: path},
				remotelog.Field{Key: "status", Value: resp.StatusCode},
				remotelog.Field{Key: "dur_ms", Value: time.Since(start).Milliseconds()},
				remotelog.Field{Key: "err", Value: lastErr},
			)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(c.retryWait):
		}
	}
	return lastErr
}

func (c *Client) uploadFile(ctx context.Context, endpoint, contentType, path string) error {
	endpointPath := safeURLPath(endpoint)
	var lastErr error
	for attempt := 0; attempt < c.retryCount; attempt++ {
		file, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("artifacts: open file: %w", err)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPut, endpoint, file)
		if err != nil {
			file.Close()
			return err
		}
		c.applyHeaders(req)
		req.Header.Set("Content-Type", contentType)

		start := time.Now()
		resp, err := c.httpClient.Do(req)
		file.Close()
		if err != nil {
			lastErr = sanitizeHTTPError(err)
			c.debug("http.artifacts.upload",
				remotelog.Field{Key: "phase", Value: "error"},
				remotelog.Field{Key: "method", Value: http.MethodPut},
				remotelog.Field{Key: "path", Value: endpointPath},
				remotelog.Field{Key: "dur_ms", Value: time.Since(start).Milliseconds()},
				remotelog.Field{Key: "err", Value: lastErr},
			)
		} else {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				c.debug("http.artifacts.upload",
					remotelog.Field{Key: "phase", Value: "done"},
					remotelog.Field{Key: "method", Value: http.MethodPut},
					remotelog.Field{Key: "path", Value: endpointPath},
					remotelog.Field{Key: "status", Value: resp.StatusCode},
					remotelog.Field{Key: "dur_ms", Value: time.Since(start).Milliseconds()},
				)
				return nil
			}
			lastErr = fmt.Errorf("artifacts: upload failed (%d)", resp.StatusCode)
			c.debug("http.artifacts.upload",
				remotelog.Field{Key: "phase", Value: "error"},
				remotelog.Field{Key: "method", Value: http.MethodPut},
				remotelog.Field{Key: "path", Value: endpointPath},
				remotelog.Field{Key: "status", Value: resp.StatusCode},
				remotelog.Field{Key: "dur_ms", Value: time.Since(start).Milliseconds()},
				remotelog.Field{Key: "err", Value: lastErr},
			)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(c.retryWait):
		}
	}
	return lastErr
}

func (c *Client) applyHeaders(req *http.Request) {
	req.Header.Set("X-API-Key", c.apiKey)
	req.Header.Set("X-User", "agent")
	req.Header.Set("X-User-Role", "agent")
	req.Header.Set("User-Agent", c.userAgent)
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

func computeFileHash(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return "", err
	}
	sum := hasher.Sum(nil)
	return hex.EncodeToString(sum), nil
}

type presignRequest struct {
	Filename    string `json:"filename"`
	ContentType string `json:"content_type,omitempty"`
	Hash        string `json:"hash,omitempty"`
	Size        int64  `json:"size"`
	Encryption  string `json:"encryption,omitempty"`
}

type presignResponse struct {
	UploadID  string    `json:"upload_id"`
	UploadURL string    `json:"upload_url"`
	ExpiresAt time.Time `json:"expires_at"`
}
