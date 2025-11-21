package goengine

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/m-sec-org/d-eyes/agent/internal/detect/scoring"
)

func TestBuildStatsRecordAndClone(t *testing.T) {
	stats := BuildStats{TotalRuleFiles: 3}
	stats.recordSuccess(5)
	stats.recordSkip("invalid")
	stats.recordSkip("")
	stats.recordRule(&Rule{ScoreHints: scoring.ScoreHints{Category: "ransom"}})

	require.Equal(t, 1, stats.LoadedRuleFiles)
	require.Equal(t, 5, stats.LoadedRules)
	require.Equal(t, 1, stats.ScoreHintsSeen)
	require.Equal(t, 2, stats.SkippedRuleFiles)
	require.Equal(t, 1, stats.SkipReasons["invalid"])
	require.Equal(t, 1, stats.SkipReasons["unknown"])
	require.InDelta(t, float64(1)/3, stats.Coverage(), 0.001)

	clone := stats.Clone()
	require.Equal(t, stats.SkipReasons, clone.SkipReasons)
	require.Equal(t, stats.LoadedRuleFiles, clone.LoadedRuleFiles)
}
