package tasks

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/m-sec-org/d-eyes/agent/pkg/config"
	"github.com/m-sec-org/d-eyes/agent/pkg/threatintel"
)

func TestAppendThreatIntelMetadataSanitizesNonCodeNotice(t *testing.T) {
	cfg := config.Default()
	cfg.ThreatIntel.Mode = threatintel.ModeLocal

	req := TaskRequest{
		Config:   cfg,
		Metadata: map[string]string{"threatintel.notice": "中文提示"},
	}
	meta := appendThreatIntelMetadata(nil, req)
	require.Equal(t, threatintel.NoticeCodeUnknown, meta["threatintel.notice"])
	require.Contains(t, meta["threatintel.notice_detail"], "中文提示")
}

func TestAppendThreatIntelMetadataRedactsAPIKeysFromNoticeDetail(t *testing.T) {
	cfg := config.Default()
	cfg.ThreatIntel.Mode = threatintel.ModeLocal
	cfg.ThreatIntel.OpenTIPAPIKey = "secret-key"

	req := TaskRequest{
		Config:   cfg,
		Metadata: map[string]string{"threatintel.notice_detail": "x-api-key=secret-key"},
	}
	meta := appendThreatIntelMetadata(nil, req)
	require.Equal(t, threatintel.NoticeCodeUnknown, meta["threatintel.notice"])
	require.NotContains(t, meta["threatintel.notice_detail"], "secret-key")
}
