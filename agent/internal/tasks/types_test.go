package tasks

import (
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/m-sec-org/d-eyes/agent/pkg/config"
	"github.com/m-sec-org/d-eyes/agent/pkg/reporting"
	"github.com/m-sec-org/d-eyes/agent/pkg/threatintel"
)

type fakeTIProvider struct {
	manager *threatintel.Manager
	err     error
	called  bool
	cfg     threatintel.Config
}

func (f *fakeTIProvider) NewManager(cfg threatintel.Config) (*threatintel.Manager, error) {
	f.called = true
	f.cfg = cfg
	if f.err != nil {
		return nil, f.err
	}
	return f.manager, nil
}

func TestApplyDefaultsInitializesThreatIntelManager(t *testing.T) {
	cfg := config.Default()
	cfg.Output.Dir = t.TempDir()
	cfg.ThreatIntel.Mode = threatintel.ModeLocal

	provider := &fakeTIProvider{manager: &threatintel.Manager{}}
	SetThreatIntelProvider(provider)
	t.Cleanup(func() { SetThreatIntelProvider(nil) })

	req := TaskRequest{Config: cfg, Manager: reporting.NewManager(cfg)}
	req.ApplyDefaults("respond")

	require.True(t, provider.called)
	require.NotNil(t, req.ThreatIntel)
	require.NotEmpty(t, provider.cfg.CacheDir)
	require.Len(t, req.Notices, 0)
}

func TestApplyDefaultsAddsNoticeWhenThreatIntelFails(t *testing.T) {
	cfg := config.Default()
	cfg.Output.Dir = t.TempDir()
	cfg.ThreatIntel.Mode = threatintel.ModeHybrid

	provider := &fakeTIProvider{err: threatintel.ErrNoActiveConnector}
	SetThreatIntelProvider(provider)
	t.Cleanup(func() { SetThreatIntelProvider(nil) })

	req := TaskRequest{Config: cfg, Manager: reporting.NewManager(cfg)}
	req.ApplyDefaults("respond")

	require.True(t, provider.called)
	require.NotNil(t, req.ThreatIntel)
	require.NotEmpty(t, req.Notices)
	require.Contains(t, req.Notices[0], "威胁情报：未配置可用")
	require.Equal(t, threatintel.NoticeCodeInitFailed, req.Metadata["threatintel.notice"])
	require.NotEmpty(t, req.Metadata["threatintel.notice_detail"])
}

func TestApplyDefaultsHybridWithoutAPIKeyFallsBackToLocal(t *testing.T) {
	cfg := config.Default()
	cfg.Output.Dir = t.TempDir()
	cfg.ThreatIntel.Mode = threatintel.ModeHybrid

	SetThreatIntelProvider(nil)

	req := TaskRequest{Config: cfg, Manager: reporting.NewManager(cfg)}
	req.ApplyDefaults("respond")

	require.NotNil(t, req.ThreatIntel)
	require.NotEmpty(t, req.Notices)
	require.True(t, strings.Contains(strings.Join(req.Notices, "\n"), "已降级为 local"))
}

func TestApplyDefaultsReadsDebugMetadata(t *testing.T) {
	cfg := config.Default()
	req := TaskRequest{
		Config:   cfg,
		Manager:  reporting.NewManager(cfg),
		Metadata: map[string]string{"debug": "true"},
	}
	req.ApplyDefaults("respond")
	require.True(t, req.Debug)
	require.Equal(t, "true", req.Metadata["debug"])
}

func TestApplyDefaultsRedactsAPIKeysInThreatIntelNotices(t *testing.T) {
	cfg := config.Default()
	cfg.Output.Dir = t.TempDir()
	cfg.ThreatIntel.Mode = threatintel.ModeHybrid
	cfg.ThreatIntel.OpenTIPAPIKey = "secret-key"

	provider := &fakeTIProvider{err: errors.New("boom secret-key")}
	SetThreatIntelProvider(provider)
	t.Cleanup(func() { SetThreatIntelProvider(nil) })

	req := TaskRequest{Config: cfg, Manager: reporting.NewManager(cfg)}
	req.ApplyDefaults("respond")

	require.Equal(t, threatintel.NoticeCodeInitFailed, req.Metadata["threatintel.notice"])
	require.NotContains(t, req.Metadata["threatintel.notice_detail"], "secret-key")
	require.NotContains(t, req.Metadata["threatintel.notice_detail"], "boom")
	require.NotContains(t, strings.Join(req.Notices, ","), "secret-key")
	require.NotContains(t, strings.Join(req.Notices, ","), "boom")
}
