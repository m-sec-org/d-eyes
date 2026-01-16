package agent

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	internal "github.com/m-sec-org/d-eyes/agent/internal"
	"github.com/m-sec-org/d-eyes/agent/internal/agent/remotelog"
	"github.com/m-sec-org/d-eyes/agent/internal/tasks"
	"github.com/m-sec-org/d-eyes/agent/pkg/config"
	serverpb "github.com/m-sec-org/d-eyes/server/proto/agentservicepb"
)

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestRemoteDebugLogsIncludeIDsAndRedactAgentToken(t *testing.T) {
	internal.SetGlobalConfig(config.Default())

	secret := "agent-token-secret"
	var buf bytes.Buffer
	debugLog := remotelog.New(remotelog.Config{
		Enabled: true,
		Output:  &buf,
		Secrets: []string{secret},
	})

	client := newFakeRemoteClient()
	store := newFakeResultStore()
	stubRunner := &fakeTaskRunner{
		err: errors.New("task failed with token=" + secret),
	}
	runner := &remoteRunner{
		cfg: config.RemoteConfig{
			AgentToken: secret,
		},
		client:   client,
		store:    store,
		debugLog: debugLog,
		resolveTask: func(string) (tasks.TaskRunner, bool) {
			return stubRunner, true
		},
	}

	lease := &serverpb.TaskLease{
		TaskId:   "task-1",
		LeaseId:  "lease-1",
		TaskType: "test.command",
	}
	require.NoError(t, runner.processLease(context.Background(), lease))

	logs := buf.String()
	require.Contains(t, logs, "task_id=task-1")
	require.Contains(t, logs, "lease_id=lease-1")
	require.NotContains(t, logs, secret)
	require.Contains(t, logs, "<redacted>")
}

func TestEventUploaderDebugDoesNotLeakAPIKeyOrURLQuery(t *testing.T) {
	secret := "api-key-secret"
	var buf bytes.Buffer
	debugLog := remotelog.New(remotelog.Config{
		Enabled: true,
		Output:  &buf,
		Secrets: []string{secret},
	})

	httpClient := &http.Client{
		Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			require.Equal(t, secret, req.Header.Get("X-API-Key"))
			return nil, errors.New("dial failed " + secret)
		}),
	}
	uploader := &eventUploader{
		client:    httpClient,
		endpoint:  "http://example.com/api/v1/events/ingest?X-API-Key=" + secret,
		apiKey:    secret,
		agentID:   "agent-1",
		agentName: "agent-1",
		debugLog:  debugLog,
	}

	err := uploader.uploadBatch(context.Background(), []byte(`[]`))
	require.Error(t, err)

	logs := buf.String()
	require.Contains(t, logs, "event=http.events.ingest")
	require.Contains(t, logs, "method=POST")
	require.Contains(t, logs, "path=/api/v1/events/ingest")
	require.NotContains(t, logs, secret)
	require.NotContains(t, logs, "X-API-Key")
	require.NotContains(t, logs, "?")
	require.Contains(t, logs, "<redacted>")
}
