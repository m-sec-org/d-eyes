package tasks

import (
	"context"
	"errors"
	"io"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/m-sec-org/d-eyes/agent/internal/debugger"
	"github.com/m-sec-org/d-eyes/agent/pkg/config"
	"github.com/m-sec-org/d-eyes/agent/pkg/reporting"
	"github.com/m-sec-org/d-eyes/agent/pkg/threatintel"
)

type debugCaptureRunner struct{}

func (debugCaptureRunner) Run(_ context.Context, req TaskRequest) (TaskResult, error) {
	if req.Debugger != nil {
		req.Debugger.PhaseStart("unit", "start", "")
		req.Debugger.Progress("unit", 1, 2, "halfway")
		req.Debugger.PhaseEnd("unit", "done")
	}
	return TaskResult{
		Metadata: map[string]string{"runner_meta": "true"},
	}, nil
}

func TestExecuteWithResultPersistsDebugMetadata(t *testing.T) {
	cfg := config.Default()
	cfg.Output.Dir = t.TempDir()
	emitter := debugger.NewEmitter(io.Discard, false)
	req := TaskRequest{
		Config:   cfg,
		Debug:    true,
		Debugger: emitter,
		Quiet:    true,
	}
	req.ApplyDefaults("unit-test")
	req.Manager = reporting.NewManager(cfg)

	summary, result, err := ExecuteWithResult(context.Background(), "unit-test", debugCaptureRunner{}, req, req.Manager)
	require.NoError(t, err)
	require.Equal(t, "unit-test", summary.Command)

	meta := result.Metadata
	require.NotNil(t, meta)
	require.Equal(t, "true", meta["runner_meta"])
	require.NotEmpty(t, meta["telemetry.debug_timeline"])
	require.NotEmpty(t, meta["telemetry.debug.summary"])
}

func TestExecuteWithResultIncludesThreatIntelMetadataInExecutionResult(t *testing.T) {
	cfg := config.Default()
	cfg.Output.Dir = t.TempDir()
	cfg.ThreatIntel.Mode = threatintel.ModeHybrid

	req := TaskRequest{
		Config: cfg,
		Quiet:  true,
	}
	req.ApplyDefaults("unit-test")
	req.Manager = reporting.NewManager(cfg)

	summary, result, err := ExecuteWithResult(context.Background(), "unit-test", debugCaptureRunner{}, req, req.Manager)
	require.NoError(t, err)

	execModel := ToExecutionResult(summary, result, nil)
	meta := execModel.Metadata
	require.NotNil(t, meta)
	require.Equal(t, "hybrid", meta["threatintel.mode_requested"])
	require.Equal(t, "local", meta["threatintel.mode_effective"])
	require.Equal(t, "false", meta["threatintel.remote_enabled"])
	require.Equal(t, "", meta["threatintel.remote_sources"])
	require.Equal(t, threatintel.NoticeCodeFallbackLocalNoAPIKey, meta["threatintel.notice"])
	require.Contains(t, meta["threatintel.notice_detail"], "已降级为 local")
}

func TestExecuteWithResultIncludesThreatIntelNoticeInServerMode(t *testing.T) {
	cfg := config.Default()
	cfg.Output.Dir = t.TempDir()
	cfg.ThreatIntel.Mode = threatintel.ModeServer

	req := TaskRequest{
		Config: cfg,
		Quiet:  true,
	}
	req.ApplyDefaults("unit-test")
	req.Manager = reporting.NewManager(cfg)

	summary, result, err := ExecuteWithResult(context.Background(), "unit-test", debugCaptureRunner{}, req, req.Manager)
	require.NoError(t, err)

	execModel := ToExecutionResult(summary, result, nil)
	meta := execModel.Metadata
	require.NotNil(t, meta)
	require.Equal(t, "server", meta["threatintel.mode_requested"])
	require.Equal(t, "server", meta["threatintel.mode_effective"])
	require.Equal(t, "false", meta["threatintel.remote_enabled"])
	require.Equal(t, "", meta["threatintel.remote_sources"])
	require.Equal(t, threatintel.NoticeCodeServerMode, meta["threatintel.notice"])
	require.Equal(t, "", meta["threatintel.notice_detail"])
}

func TestExecuteWithResultIncludesThreatIntelNoticeWhenInitFailed(t *testing.T) {
	cfg := config.Default()
	cfg.Output.Dir = t.TempDir()
	cfg.ThreatIntel.Mode = threatintel.ModeHybrid

	provider := &fakeTIProvider{err: errors.New("boom")}
	SetThreatIntelProvider(provider)
	t.Cleanup(func() { SetThreatIntelProvider(nil) })

	req := TaskRequest{
		Config: cfg,
		Quiet:  true,
	}
	req.ApplyDefaults("unit-test")
	req.Manager = reporting.NewManager(cfg)

	summary, result, err := ExecuteWithResult(context.Background(), "unit-test", debugCaptureRunner{}, req, req.Manager)
	require.NoError(t, err)

	execModel := ToExecutionResult(summary, result, nil)
	meta := execModel.Metadata
	require.NotNil(t, meta)
	require.Equal(t, "hybrid", meta["threatintel.mode_requested"])
	require.Equal(t, "local", meta["threatintel.mode_effective"])
	require.Equal(t, threatintel.NoticeCodeInitFailed, meta["threatintel.notice"])
	require.NotEmpty(t, meta["threatintel.notice_detail"])
}
