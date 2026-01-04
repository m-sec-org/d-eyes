package threatintel

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestHybridRemoteHashLookupCachesByTTL(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/search/hash" {
			http.NotFound(w, r)
			return
		}
		require.Equal(t, "key", r.Header.Get("x-api-key"))
		require.Equal(t, "a"+strings.Repeat("b", 63), r.URL.Query().Get("request"))
		calls.Add(1)
		w.Header().Set("Cache-Control", "max-age=60")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"verdict":    "malicious",
			"confidence": "high",
		})
	}))
	t.Cleanup(server.Close)

	cfg := Config{
		Mode:                 ModeHybrid,
		OpenTIPAPIKey:        "key",
		OpenTIPBaseURL:       server.URL,
		CacheTTL:             24 * time.Hour,
		CacheSize:            10,
		HTTPTimeout:          time.Second,
		MaxParallelPerSource: 1,
	}
	mgr, err := NewManager(cfg)
	require.NoError(t, err)

	now := time.Unix(0, 0)
	mgr.clock = func() time.Time { return now }

	hash := "a" + strings.Repeat("b", 63)
	findings, err := mgr.LookupIndicator(context.Background(), IndicatorHash, hash, nil)
	require.NoError(t, err)
	require.Equal(t, int32(1), calls.Load())
	require.True(t, hasSource(findings, "opentip"))

	_, err = mgr.LookupIndicator(context.Background(), IndicatorHash, hash, nil)
	require.NoError(t, err)
	require.Equal(t, int32(1), calls.Load())

	now = now.Add(61 * time.Second)
	_, err = mgr.LookupIndicator(context.Background(), IndicatorHash, hash, nil)
	require.NoError(t, err)
	require.Equal(t, int32(2), calls.Load())
}

func TestHybridRemoteQuotaPausesAndRetriesAfter(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/search/hash" {
			http.NotFound(w, r)
			return
		}
		call := calls.Add(1)
		if call == 1 {
			w.Header().Set("Retry-After", "60")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"verdict":    "malicious",
			"confidence": "high",
		})
	}))
	t.Cleanup(server.Close)

	cfg := Config{
		Mode:                 ModeHybrid,
		OpenTIPAPIKey:        "key",
		OpenTIPBaseURL:       server.URL,
		CacheTTL:             24 * time.Hour,
		CacheSize:            10,
		HTTPTimeout:          time.Second,
		MaxParallelPerSource: 1,
	}
	mgr, err := NewManager(cfg)
	require.NoError(t, err)

	now := time.Unix(0, 0)
	mgr.clock = func() time.Time { return now }

	hash := strings.Repeat("c", 64)
	findings, err := mgr.LookupIndicator(context.Background(), IndicatorHash, hash, nil)
	require.NoError(t, err)
	require.Equal(t, int32(1), calls.Load())
	require.False(t, hasSource(findings, "opentip"))
	require.Contains(t, mgr.NoticeCodes(), NoticeCodeRemoteQuotaExceeded)
	require.Contains(t, mgr.NoticeCodes(), NoticeCodeRemotePaused)
	require.False(t, mgr.RemoteEnabled())
	require.Equal(t, ModeLocal, mgr.Mode())

	_, err = mgr.LookupIndicator(context.Background(), IndicatorHash, hash, nil)
	require.NoError(t, err)
	require.Equal(t, int32(1), calls.Load())

	now = now.Add(61 * time.Second)
	findings, err = mgr.LookupIndicator(context.Background(), IndicatorHash, hash, nil)
	require.NoError(t, err)
	require.Equal(t, int32(2), calls.Load())
	require.True(t, hasSource(findings, "opentip"))
}

func TestHybridRemoteQuotaDefaultsRetryAfterWhenMissing(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/search/hash" {
			http.NotFound(w, r)
			return
		}
		calls.Add(1)
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	t.Cleanup(server.Close)

	cfg := Config{
		Mode:                 ModeHybrid,
		OpenTIPAPIKey:        "key",
		OpenTIPBaseURL:       server.URL,
		CacheTTL:             24 * time.Hour,
		CacheSize:            10,
		HTTPTimeout:          time.Second,
		MaxParallelPerSource: 1,
	}
	mgr, err := NewManager(cfg)
	require.NoError(t, err)

	now := time.Unix(0, 0)
	mgr.clock = func() time.Time { return now }

	hash := strings.Repeat("e", 64)
	findings, err := mgr.LookupIndicator(context.Background(), IndicatorHash, hash, nil)
	require.NoError(t, err)
	require.Equal(t, int32(1), calls.Load())
	require.False(t, hasSource(findings, "opentip"))
	require.Contains(t, mgr.NoticeCodes(), NoticeCodeRemoteQuotaExceeded)
	require.Contains(t, mgr.NoticeCodes(), NoticeCodeRemotePaused)
	require.False(t, mgr.RemoteEnabled())
	require.Equal(t, ModeLocal, mgr.Mode())
	require.Contains(t, strings.Join(mgr.Notices(), "; "), "retry_after=30s")

	_, err = mgr.LookupIndicator(context.Background(), IndicatorHash, hash, nil)
	require.NoError(t, err)
	require.Equal(t, int32(1), calls.Load())
}

func TestHybridRemoteTemporaryErrorPausesAndRecovers(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/search/hash" {
			http.NotFound(w, r)
			return
		}
		call := calls.Add(1)
		if call == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"verdict":    "malicious",
			"confidence": "high",
		})
	}))
	t.Cleanup(server.Close)

	cfg := Config{
		Mode:                 ModeHybrid,
		OpenTIPAPIKey:        "key",
		OpenTIPBaseURL:       server.URL,
		CacheTTL:             24 * time.Hour,
		CacheSize:            10,
		HTTPTimeout:          time.Second,
		MaxParallelPerSource: 1,
	}
	mgr, err := NewManager(cfg)
	require.NoError(t, err)

	now := time.Unix(0, 0)
	mgr.clock = func() time.Time { return now }

	hash := strings.Repeat("f", 64)
	findings, err := mgr.LookupIndicator(context.Background(), IndicatorHash, hash, nil)
	require.NoError(t, err)
	require.Equal(t, int32(1), calls.Load())
	require.False(t, hasSource(findings, "opentip"))
	require.Contains(t, mgr.NoticeCodes(), NoticeCodeProviderError)
	require.Contains(t, mgr.NoticeCodes(), NoticeCodeRemotePaused)
	require.False(t, mgr.RemoteEnabled())
	require.Equal(t, ModeLocal, mgr.Mode())
	require.Contains(t, strings.Join(mgr.Notices(), "; "), "status=500")
	require.Contains(t, strings.Join(mgr.Notices(), "; "), "retry_after=30s")

	_, err = mgr.LookupIndicator(context.Background(), IndicatorHash, hash, nil)
	require.NoError(t, err)
	require.Equal(t, int32(1), calls.Load())

	now = now.Add(31 * time.Second)
	findings, err = mgr.LookupIndicator(context.Background(), IndicatorHash, hash, nil)
	require.NoError(t, err)
	require.Equal(t, int32(2), calls.Load())
	require.True(t, hasSource(findings, "opentip"))
	require.True(t, mgr.RemoteEnabled())
	require.Equal(t, ModeHybrid, mgr.Mode())
}

func TestHybridRemoteMetaDefenderFileScanFallsBackFromHashLookup(t *testing.T) {
	hash := strings.Repeat("d", 64)
	var uploadCalls atomic.Int32
	var pollCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/hash/"):
			require.Equal(t, "key", r.Header.Get("apikey"))
			w.WriteHeader(http.StatusNotFound)
		case r.URL.Path == "/file" && r.Method == http.MethodPost:
			require.Equal(t, "key", r.Header.Get("apikey"))
			uploadCalls.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data_id": "id-1",
				"sha256":  hash,
			})
		case r.URL.Path == "/file/id-1" && r.Method == http.MethodGet:
			require.Equal(t, "key", r.Header.Get("apikey"))
			pollCalls.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"scan_results": map[string]any{
					"progress_percentage": 100,
					"scan_all_result_a":   "malicious",
					"scan_all_result_i":   "high",
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	cfg := Config{
		Mode:                 ModeHybrid,
		MetaDefenderAPIKey:   "key",
		MetaDefenderBaseURL:  server.URL,
		CacheTTL:             24 * time.Hour,
		CacheSize:            10,
		HTTPTimeout:          time.Second,
		MaxParallelPerSource: 1,
	}
	mgr, err := NewManager(cfg)
	require.NoError(t, err)

	mgr.clock = func() time.Time { return time.Unix(0, 0) }

	file := filepath.Join(t.TempDir(), "sample.bin")
	require.NoError(t, os.WriteFile(file, []byte("payload"), 0o600))

	findings, err := mgr.LookupFile(context.Background(), file, nil)
	require.NoError(t, err)
	require.Equal(t, int32(1), uploadCalls.Load())
	require.Equal(t, int32(1), pollCalls.Load())
	require.True(t, hasSource(findings, "metadefender"))
}

func hasSource(findings []Finding, source string) bool {
	for _, finding := range findings {
		if finding.Source == source {
			return true
		}
	}
	return false
}
