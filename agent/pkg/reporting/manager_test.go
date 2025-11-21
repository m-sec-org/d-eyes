package reporting

import (
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/m-sec-org/d-eyes/agent/pkg/config"
)

func TestCreateFileSanitisesPaths(t *testing.T) {
	cfg := config.Default()
	cfg.Output.Dir = t.TempDir()
	mgr := NewManager(cfg)

	file, path, err := mgr.CreateFile("respond/../danger", " My Report ", ".json")
	require.NoError(t, err)
	file.Close()

	require.FileExists(t, path)
	require.NotContains(t, path, "..")
	require.Contains(t, path, filepath.Join(cfg.Output.Dir, "respond"))
	require.Contains(t, path, "danger")
}

func TestPrintSummaryWritesToStdout(t *testing.T) {
	cfg := config.Default()
	cfg.Output.Dir = t.TempDir()
	mgr := NewManager(cfg)
	summary := Summary{
		Command:  "respond",
		Duration: 2 * time.Second,
		Outputs:  []OutputRecord{{Label: "report", Path: filepath.Join(cfg.Output.Dir, "respond", "report.json")}},
		Risks:    map[string]int{"high": 1},
		Notes:    []string{"done"},
		Status:   "完成",
	}

	r, w, _ := os.Pipe()
	orig := os.Stdout
	os.Stdout = w
	mgr.PrintSummary(summary)
	w.Close()
	os.Stdout = orig

	output, _ := io.ReadAll(r)
	text := string(output)
	require.Contains(t, text, "respond 完成")
	require.Contains(t, text, "生成报告")
	require.Contains(t, text, "风险统计")
	require.Contains(t, text, "done")
}
