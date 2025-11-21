package remote

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	serverpb "github.com/m-sec-org/d-eyes/server/proto/agentservicepb"
)

func TestFileStoreSavePendingAndDelete(t *testing.T) {
	dir := t.TempDir()
	store, err := NewFileStore(dir)
	require.NoError(t, err)

	req := &serverpb.ReportResultRequest{
		AgentId:      "agent-a",
		TaskId:       "task-1",
		LeaseId:      "lease-1",
		Status:       "succeeded",
		ErrorMessage: "",
		Metadata: map[string]string{
			"env": "prod",
		},
		ExitCode: 0,
	}
	require.NoError(t, store.Save(req))

	pending, err := store.Pending()
	require.NoError(t, err)
	require.Len(t, pending, 1)
	require.Equal(t, "task-1", pending[0].GetTaskId())
	require.Equal(t, "prod", pending[0].GetMetadata()["env"])

	require.NoError(t, store.Delete("lease-1"))
	pending, err = store.Pending()
	require.NoError(t, err)
	require.Len(t, pending, 0)
}

func TestFileStorePendingSkipsCorruptRecords(t *testing.T) {
	dir := t.TempDir()
	store, err := NewFileStore(dir)
	require.NoError(t, err)

	corruptPath := filepath.Join(dir, "bad.json")
	require.NoError(t, os.WriteFile(corruptPath, []byte("{not-json"), 0o600))

	req := &serverpb.ReportResultRequest{
		AgentId: "agent-b",
		TaskId:  "task-2",
		LeaseId: "lease-2",
		Status:  "failed",
	}
	require.NoError(t, store.Save(req))

	pending, err := store.Pending()
	require.NoError(t, err)
	require.Len(t, pending, 1)
	require.Equal(t, "task-2", pending[0].GetTaskId())
}

func TestFileStoreSaveCreatesFiles(t *testing.T) {
	dir := t.TempDir()
	store, err := NewFileStore(dir)
	require.NoError(t, err)

	req := &serverpb.ReportResultRequest{
		AgentId: "agent-c",
		TaskId:  "task-3",
		LeaseId: "lease-3",
		Status:  "pending",
	}
	require.NoError(t, store.Save(req))

	path := filepath.Join(dir, "lease-3.json")
	info, err := os.Stat(path)
	require.NoError(t, err)
	require.False(t, info.IsDir())
	require.True(t, info.Size() > 0)

	// Ensure repeated save overwrites.
	time.Sleep(10 * time.Millisecond)
	require.NoError(t, store.Save(req))
	info2, err := os.Stat(path)
	require.NoError(t, err)
	require.True(t, info2.ModTime().After(info.ModTime()))
}
