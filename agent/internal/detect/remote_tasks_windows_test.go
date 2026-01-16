//go:build windows

package detect

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/m-sec-org/d-eyes/agent/internal/tasks"
	"github.com/m-sec-org/d-eyes/agent/pkg/config"
	"github.com/m-sec-org/d-eyes/agent/pkg/exit"
	"github.com/m-sec-org/d-eyes/agent/pkg/reporting"
)

func TestRemoteDetectMemscanRunnerRequiresApproval(t *testing.T) {
	cfg := config.Default()
	cfg.Output.Dir = t.TempDir()
	manager := reporting.NewManager(cfg)

	req := tasks.TaskRequest{
		Name:     "memscan-task",
		Config:   cfg,
		Manager:  manager,
		Flags:    map[string]any{"pid": 1},
		Metadata: map[string]string{},
	}

	result, err := (remoteDetectMemscanRunner{}).Run(context.Background(), req)
	require.Error(t, err)

	var coder exit.ExitCoder
	require.True(t, errors.As(err, &coder))
	require.Equal(t, 65, coder.ExitCode())
	require.Equal(t, memscanErrorCodeApprovalRequired, result.Metadata["error_code"])
}

func TestRemoteDetectMemscanRunnerRequiresEvidenceApproval(t *testing.T) {
	cfg := config.Default()
	cfg.Output.Dir = t.TempDir()
	manager := reporting.NewManager(cfg)

	req := tasks.TaskRequest{
		Name:    "memscan-task",
		Config:  cfg,
		Manager: manager,
		Flags: map[string]any{
			"pid":      1,
			"evidence": true,
		},
		Metadata: map[string]string{
			memscanApprovalRequiredKey: "true",
			memscanApprovedKey:         "true",
		},
	}

	result, err := (remoteDetectMemscanRunner{}).Run(context.Background(), req)
	require.Error(t, err)

	var coder exit.ExitCoder
	require.True(t, errors.As(err, &coder))
	require.Equal(t, 65, coder.ExitCode())
	require.Equal(t, memscanErrorCodeEvidenceRequired, result.Metadata["error_code"])
}

func TestRemoteDetectMemscanRunnerWritesReportToDisk(t *testing.T) {
	cfg := config.Default()
	cfg.Output.Dir = t.TempDir()
	manager := reporting.NewManager(cfg)
	pid := os.Getpid()

	req := tasks.TaskRequest{
		Name:    "memscan-task",
		Config:  cfg,
		Manager: manager,
		Timeout: 5 * time.Second,
		Flags: map[string]any{
			"pid":         pid,
			"rwx_only":    false,
			"max_bytes":   1024,
			"max_regions": 1,
		},
		Metadata: map[string]string{
			memscanApprovalRequiredKey: "true",
			memscanApprovedKey:         "true",
		},
	}

	result, err := (remoteDetectMemscanRunner{}).Run(context.Background(), req)
	require.NoError(t, err)

	var reportPath string
	for _, out := range result.Outputs {
		if out.Label == "内存扫描报告" {
			reportPath = out.Path
			break
		}
	}
	require.NotEmpty(t, reportPath)
	data, err := os.ReadFile(reportPath)
	require.NoError(t, err)

	var report memscanReport
	require.NoError(t, json.Unmarshal(data, &report))
	require.Equal(t, "detect memscan", report.Command)
	require.Equal(t, pid, report.Options.Pid)
	require.False(t, report.Options.All)
	require.False(t, report.Options.Evidence)
	require.False(t, report.Options.MiniDump)
}
