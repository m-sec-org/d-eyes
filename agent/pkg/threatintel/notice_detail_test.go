package threatintel

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSanitizeNoticeDetailTruncatesAndRedacts(t *testing.T) {
	cfg := Config{OpenTIPAPIKey: "secret-key"}
	raw := "line1\nline2\tsecret-key " + strings.Repeat("x", 400)

	sanitized := SanitizeNoticeDetail(raw, cfg)
	require.NotContains(t, sanitized, "secret-key")
	require.NotContains(t, sanitized, "\n")
	require.NotContains(t, sanitized, "\t")
	require.LessOrEqual(t, len([]rune(sanitized)), maxNoticeDetailRunes)
}

func TestFormatNoticeDetailKeepsShortFields(t *testing.T) {
	cfg := Config{OpenTIPAPIKey: "secret-key"}
	detail := FormatNoticeDetail(cfg, "quota exceeded", NoticeField{Key: "provider", Value: "opentip"}, NoticeField{Key: "retry_after", Value: "60"})
	require.Contains(t, detail, "quota exceeded")
	require.Contains(t, detail, "provider=opentip")
	require.Contains(t, detail, "retry_after=60")
	require.LessOrEqual(t, len([]rune(detail)), maxNoticeDetailRunes)
	require.NotContains(t, detail, "secret-key")
}
