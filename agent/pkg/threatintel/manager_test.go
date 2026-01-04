package threatintel

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestNewManagerValidatesSources(t *testing.T) {
	mgr, err := NewManager(Config{Mode: ModeHybrid})
	require.NoError(t, err)
	require.NotNil(t, mgr)
	require.NotEmpty(t, mgr.Notices())
	require.Equal(t, []string{NoticeCodeFallbackLocalNoAPIKey}, mgr.NoticeCodes())

	findings, err := mgr.LookupIndicator(context.Background(), IndicatorIP, "8.8.8.8", nil)
	require.NoError(t, err)
	require.NotEmpty(t, findings[0].Source)
	require.Empty(t, findings[0].Notice)

	mgr, err = NewManager(Config{Mode: ModeLocal})
	require.NoError(t, err)
	require.NotNil(t, mgr)
	require.Empty(t, mgr.Notices())
}

func TestLookupIndicatorCachesAndExpires(t *testing.T) {
	mgr, err := NewManager(Config{Mode: ModeLocal, CacheTTL: time.Minute, CacheSize: 8})
	require.NoError(t, err)

	now := time.Unix(0, 0)
	mgr.clock = func() time.Time { return now }

	first, err := mgr.LookupIndicator(context.Background(), IndicatorIP, "1.1.1.1", map[string]string{"source": "first"})
	require.NoError(t, err)
	require.Len(t, first, 1)
	require.Equal(t, now, first[0].ObservedAt)

	now = now.Add(30 * time.Second)
	second, err := mgr.LookupIndicator(context.Background(), IndicatorIP, "1.1.1.1", map[string]string{"source": "second"})
	require.NoError(t, err)
	require.Equal(t, first[0].ObservedAt, second[0].ObservedAt)
	require.Equal(t, "first", second[0].Context["source"])

	now = now.Add(2 * time.Minute)
	third, err := mgr.LookupIndicator(context.Background(), IndicatorIP, "1.1.1.1", map[string]string{"source": "third"})
	require.NoError(t, err)
	require.NotEqual(t, first[0].ObservedAt, third[0].ObservedAt)
}

func TestLookupFileClassifiesAndCaches(t *testing.T) {
	mgr, err := NewManager(Config{Mode: ModeLocal})
	require.NoError(t, err)

	tmpFile := t.TempDir() + "/sample.exe"
	require.NoError(t, os.WriteFile(tmpFile, []byte("malware"), 0o600))

	findings, err := mgr.LookupFile(context.Background(), tmpFile, map[string]string{"case": "A"})
	require.NoError(t, err)
	require.Equal(t, IndicatorHash, findings[0].Kind)
	require.Equal(t, "suspicious", findings[0].Classification)
	require.Equal(t, "A", findings[0].Context["case"])

	findings2, err := mgr.LookupFile(context.Background(), tmpFile, map[string]string{"case": "B"})
	require.NoError(t, err)
	require.Equal(t, findings[0].Indicator, findings2[0].Indicator)
	require.Equal(t, "A", findings2[0].Context["case"])
}

func TestLookupIndicatorValidatesInput(t *testing.T) {
	mgr, err := NewManager(Config{Mode: ModeLocal})
	require.NoError(t, err)
	_, err = mgr.LookupIndicator(context.Background(), IndicatorDomain, "", nil)
	require.Error(t, err)
}
