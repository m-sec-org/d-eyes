package detect

import (
	"context"
	"flag"
	"os"
	"runtime"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/urfave/cli/v2"

	"github.com/m-sec-org/d-eyes/agent/internal/detect/engine"
	"github.com/m-sec-org/d-eyes/agent/internal/detect/memscan"
	"github.com/m-sec-org/d-eyes/agent/pkg/config"
	"github.com/m-sec-org/d-eyes/agent/pkg/reporting"
)

func TestValidateMemscanTargets(t *testing.T) {
	require.Error(t, validateMemscanTargets(0, false))
	require.NoError(t, validateMemscanTargets(1234, false))
	require.NoError(t, validateMemscanTargets(0, true))
	require.Error(t, validateMemscanTargets(1234, true))
}

func TestNormalizeRiskLevel(t *testing.T) {
	require.Equal(t, "", normalizeRiskLevel(""))
	require.Equal(t, "High", normalizeRiskLevel("High"))
	require.Equal(t, "High", normalizeRiskLevel("High (partial)"))
	require.Equal(t, "Medium", normalizeRiskLevel("  Medium   (partial)  "))
}

func TestMemscanCommandUnsupportedOnNonWindows(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unsupported scenario only applies to non-Windows")
	}

	opt := NewDetectPluginYaraMemScan()
	app := cli.NewApp()
	set := flag.NewFlagSet("test", flag.ContinueOnError)
	ctx := cli.NewContext(app, set, nil)
	ctx.Context = context.Background()

	err := opt.Action(ctx)
	require.Error(t, err)
	exitCoder, ok := err.(interface{ ExitCode() int })
	require.True(t, ok)
	require.NotEqual(t, 0, exitCoder.ExitCode())
	require.Contains(t, err.Error(), "supported on Windows")
}

func TestClassifyProcessSkipReasonUsesErrno(t *testing.T) {
	require.Equal(t, string(memscan.ReadErrorAccessDenied), classifyProcessSkipReason(syscall.Errno(5)))
	require.Equal(t, string(memscan.ReadErrorInvalidParameter), classifyProcessSkipReason(syscall.Errno(87)))
	require.Equal(t, string(memscan.ReadErrorInvalidAddress), classifyProcessSkipReason(syscall.Errno(487)))
	require.Equal(t, string(memscan.ReadErrorNoAccess), classifyProcessSkipReason(syscall.Errno(998)))
	require.Equal(t, string(memscan.ReadErrorOther), classifyProcessSkipReason(syscall.Errno(123456)))
}

func TestWriteMemscanHexdumpEvidence(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := config.Default()
	cfg.Output.Dir = tmpDir
	manager := reporting.NewManager(cfg)

	chunk := memscan.Chunk{
		Region: memscan.Region{
			Base:    uintptr(0x1000),
			Size:    uintptr(0x2000),
			Protect: 0x40,
		},
		Address: uintptr(0x1000),
		Data:    []byte("xxxxd-eyes-memscan-e2eYYYY"),
	}
	match := engine.Match{
		RuleName: "TEST_RULE",
		Tags:     []string{"e2e"},
		Strings: []engine.MatchedString{
			{Identifier: "$a", Offsets: []int{4}},
		},
	}

	opt := &YaraMemScanOptions{
		EvidenceMaxBytes:     16,
		EvidenceContextBytes: 0,
	}

	ev, err := writeMemscanHexdumpEvidence(manager, 123, "proc", chunk, match, opt)
	require.NoError(t, err)
	require.Equal(t, "hexdump", ev.Kind)
	require.NotEmpty(t, ev.Path)
	require.Equal(t, uint64(0x1000+4), ev.StartAddress)
	require.NotEmpty(t, ev.SHA256)

	raw, err := os.ReadFile(ev.Path)
	require.NoError(t, err)
	require.Contains(t, string(raw), "kind: hexdump")
	require.Contains(t, string(raw), "rule: TEST_RULE")
	require.Contains(t, string(raw), "sha256:")
}

func TestHexdumpOffsetsAggSummary(t *testing.T) {
	var agg hexdumpOffsetsAgg
	chunk := memscan.Chunk{Address: uintptr(0x1000)}

	agg.add(chunk, engine.Match{
		Strings: []engine.MatchedString{
			{Identifier: "$a", Offsets: []int{4}},
		},
	}, 0)

	agg.add(chunk, engine.Match{
		Strings: []engine.MatchedString{
			{Identifier: "$a", Offsets: []int{4, 20}},
		},
	}, 0)

	summary := agg.summary()
	require.NotNil(t, summary)
	require.Equal(t, 2, summary.MatchCount)
	require.Equal(t, 3, summary.OffsetsObserved)
	require.Equal(t, 2, summary.OffsetsCaptured)
	require.False(t, summary.OffsetsTruncated)
	require.Len(t, summary.Strings, 1)
	require.Equal(t, "$a", summary.Strings[0].Identifier)
	require.Equal(t, []uint64{0x1004, 0x1014}, summary.Strings[0].Offsets)
}

func TestHexdumpOffsetsAggTruncates(t *testing.T) {
	var agg hexdumpOffsetsAgg
	chunk := memscan.Chunk{Address: uintptr(0x1000)}

	agg.add(chunk, engine.Match{
		Strings: []engine.MatchedString{
			{Identifier: "$a", Offsets: []int{4, 20}},
		},
	}, 1)

	summary := agg.summary()
	require.NotNil(t, summary)
	require.Equal(t, 1, summary.MatchCount)
	require.Equal(t, 2, summary.OffsetsObserved)
	require.Equal(t, 1, summary.OffsetsCaptured)
	require.True(t, summary.OffsetsTruncated)
	require.Len(t, summary.Strings, 1)
	require.Equal(t, []uint64{0x1004}, summary.Strings[0].Offsets)
}

func TestPlannedMemscanHexdumpBytes(t *testing.T) {
	chunk := memscan.Chunk{
		Address: uintptr(0x1000),
		Data:    make([]byte, 30),
	}
	match := engine.Match{
		Strings: []engine.MatchedString{
			{Identifier: "$a", Offsets: []int{10}},
		},
	}
	opt := &YaraMemScanOptions{
		EvidenceContextBytes: 5,
		EvidenceMaxBytes:     8,
	}

	bytes, err := plannedMemscanHexdumpBytes(chunk, match, opt)
	require.NoError(t, err)
	require.Equal(t, uint64(8), bytes)
}
