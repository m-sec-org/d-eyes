package artifacts

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestClientUpload(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "sample.bin")
	require.NoError(t, os.WriteFile(filePath, []byte("artifact-payload"), 0o644))

	var presignCalls, uploadCalls atomic.Int32
	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/artifacts/presign", func(w http.ResponseWriter, r *http.Request) {
		presignCalls.Add(1)
		require.Equal(t, "application/json", r.Header.Get("Content-Type"))
		require.Equal(t, "agent-token", r.Header.Get("X-API-Key"))
		var payload map[string]any
		require.NoError(t, json.NewDecoder(r.Body).Decode(&payload))
		require.Equal(t, "sample.bin", payload["filename"])
		require.Equal(t, "application/octet-stream", payload["content_type"])
		require.Equal(t, "aes256-gcm", payload["encryption"])

		resp := map[string]any{
			"upload_id":  "token-123",
			"upload_url": srv.URL + "/api/v1/artifacts/upload/token-123",
			"expires_at": time.Now().Add(time.Minute),
		}
		encoder := json.NewEncoder(w)
		require.NoError(t, encoder.Encode(resp))
	})
	mux.HandleFunc("/api/v1/artifacts/upload/token-123", func(w http.ResponseWriter, r *http.Request) {
		uploadCalls.Add(1)
		require.Equal(t, "PUT", r.Method)
		require.Equal(t, "agent-token", r.Header.Get("X-API-Key"))
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		require.Equal(t, []byte("artifact-payload"), body)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"uploaded"}`))
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		if isPermissionDenied(err) {
			t.Skipf("skip artifacts client tests: %v", err)
		}
		t.Fatalf("listen tcp: %v", err)
	}
	srv = httptest.NewUnstartedServer(mux)
	srv.Listener = ln
	srv.Start()
	defer srv.Close()

	client, err := NewClient(Config{
		BaseURL:    srv.URL,
		APIKey:     "agent-token",
		RetryCount: 2,
	})
	require.NoError(t, err)

	ctx := context.Background()
	result, err := client.Upload(ctx, UploadInput{
		Path:        filePath,
		Encryption:  "aes256-gcm",
		ContentType: "",
	})
	require.NoError(t, err)
	require.Equal(t, "token-123", result.Token)
	require.Equal(t, int64(len("artifact-payload")), result.Size)

	require.Equal(t, int32(1), presignCalls.Load())
	require.Equal(t, int32(1), uploadCalls.Load())
}

func isPermissionDenied(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EPERM) {
		return true
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return isPermissionDenied(opErr.Err)
	}
	var sysErr *os.SyscallError
	if errors.As(err, &sysErr) {
		return isPermissionDenied(sysErr.Err)
	}
	return false
}
