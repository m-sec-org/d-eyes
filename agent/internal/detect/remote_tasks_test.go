//go:build linux || windows || darwin

package detect

import (
	"context"
	"errors"
	"os"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/m-sec-org/d-eyes/agent/internal/tasks"
	"github.com/m-sec-org/d-eyes/agent/pkg/config"
	"github.com/m-sec-org/d-eyes/agent/pkg/exit"
	"github.com/m-sec-org/d-eyes/agent/pkg/reporting"
)

func TestRemoteDetectDiagRunnerWritesReport(t *testing.T) {
	cfg := config.Default()
	cfg.Output.Dir = t.TempDir()
	manager := reporting.NewManager(cfg)

	req := tasks.TaskRequest{
		Name:    "diag-task",
		Config:  cfg,
		Manager: manager,
		Flags: map[string]any{
			"backend": "auto",
			"rule":    "",
		},
	}

	result, err := (remoteDetectDiagRunner{}).Run(context.Background(), req)
	require.NoError(t, err)
	require.Len(t, result.Outputs, 1)
	require.Equal(t, "诊断报告", result.Outputs[0].Label)
	require.NotEmpty(t, result.Outputs[0].Path)
	_, statErr := os.Stat(result.Outputs[0].Path)
	require.NoError(t, statErr)
}

func TestValidateMemscanApproval(t *testing.T) {
	code, err := validateMemscanApproval(nil, false)
	require.Error(t, err)
	require.Equal(t, memscanErrorCodeApprovalRequired, code)

	code, err = validateMemscanApproval(map[string]string{
		memscanApprovalRequiredKey: "true",
		memscanApprovedKey:         "true",
	}, false)
	require.NoError(t, err)
	require.Empty(t, code)

	code, err = validateMemscanApproval(map[string]string{
		memscanApprovalRequiredKey: "true",
		memscanApprovedKey:         "true",
	}, true)
	require.Error(t, err)
	require.Equal(t, memscanErrorCodeEvidenceRequired, code)

	code, err = validateMemscanApproval(map[string]string{
		memscanApprovalRequiredKey: "true",
		memscanApprovedKey:         "true",
		memscanEvidenceApprovedKey: "true",
	}, true)
	require.NoError(t, err)
	require.Empty(t, code)
}

func TestRemoteDetectMemscanRunnerRejectsNonWindows(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("non-windows regression test")
	}
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

	_, err := (remoteDetectMemscanRunner{}).Run(context.Background(), req)
	require.Error(t, err)

	var coder exit.ExitCoder
	require.True(t, errors.As(err, &coder))
	require.Equal(t, 1, coder.ExitCode())
}
