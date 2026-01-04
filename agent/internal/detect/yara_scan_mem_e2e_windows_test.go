//go:build windows

package detect

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/shirou/gopsutil/v4/process"
	"github.com/stretchr/testify/require"
	"github.com/urfave/cli/v2"
	"golang.org/x/sys/windows"

	"github.com/m-sec-org/d-eyes/agent/internal"
	"github.com/m-sec-org/d-eyes/agent/internal/detect/backend"
	"github.com/m-sec-org/d-eyes/agent/internal/detect/memscan"
	"github.com/m-sec-org/d-eyes/agent/pkg/config"
)

var (
	memscanKernel32     = windows.NewLazySystemDLL("kernel32.dll")
	procVirtualAllocE2E = memscanKernel32.NewProc("VirtualAlloc")
	procVirtualFreeE2E  = memscanKernel32.NewProc("VirtualFree")
)

const (
	memCommit  = 0x1000
	memReserve = 0x2000
	memRelease = 0x8000

	pageExecuteReadWrite = 0x40

	memscanRegionSizeE2E = 64 * 1024
	memscanMaxBytesE2E   = 1024

	memscanRuleNameE2E   = "D_EYES_MEMSCAN_E2E"
	memscanRuleNeedleE2E = "d-eyes-memscan-e2e"
	memscanRuleTagE2E    = "e2e"

	memscanAllHelperEnv = "D_EYES_MEMSCAN_ALL_HELPER"
	memscanMinidumpEnv  = "D_EYES_MEMSCAN_MINIDUMP_E2E"
)

func virtualAllocRWXE2E(size uintptr) (uintptr, error) {
	addr, _, e1 := procVirtualAllocE2E.Call(
		0,
		size,
		memCommit|memReserve,
		pageExecuteReadWrite,
	)
	if addr == 0 {
		if e1 != syscall.Errno(0) {
			return 0, e1
		}
		return 0, syscall.EINVAL
	}
	return addr, nil
}

func virtualFreeE2E(addr uintptr) error {
	r1, _, e1 := procVirtualFreeE2E.Call(addr, 0, memRelease)
	if r1 == 0 {
		if e1 != syscall.Errno(0) {
			return e1
		}
		return syscall.EINVAL
	}
	return nil
}

func TestDetectMemscanWindowsE2E(t *testing.T) {
	tmpDir := t.TempDir()

	prevCfg := internal.GetGlobalConfig()
	cfg := config.Default()
	cfg.Output.Dir = filepath.Join(tmpDir, "reports")
	internal.SetGlobalConfig(cfg)
	t.Cleanup(func() {
		internal.SetGlobalConfig(prevCfg)
	})

	ruleDir := filepath.Join(tmpDir, "rules")
	require.NoError(t, os.MkdirAll(ruleDir, 0o755))

	rulePath := filepath.Join(ruleDir, "memscan_e2e.yar")
	rule := `rule ` + memscanRuleNameE2E + ` : ` + memscanRuleTagE2E + ` test {
  strings:
    $a = "` + memscanRuleNeedleE2E + `"
  condition:
    $a
}
`
	require.NoError(t, os.WriteFile(rulePath, []byte(rule), 0o600))

	addr, err := virtualAllocRWXE2E(memscanRegionSizeE2E)
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, virtualFreeE2E(addr))
	})

	payload := []byte(memscanRuleNeedleE2E)
	dst := unsafe.Slice((*byte)(unsafe.Pointer(addr)), len(payload))
	copy(dst, payload)

	opt := NewDetectPluginYaraMemScan()
	opt.Pid = os.Getpid()
	opt.All = false
	opt.RulePath = rulePath
	opt.Backend = string(backend.ModePortable)
	opt.RWXOnly = true
	opt.MaxBytes = memscanMaxBytesE2E
	opt.MaxRegions = 0
	opt.Timeout = 10 * time.Second
	opt.Evidence = true
	opt.EvidenceMaxBytes = 1024
	opt.EvidenceContextBytes = 0
	opt.EvidenceMaxArtifacts = 4

	app := cli.NewApp()
	set := flag.NewFlagSet("test", flag.ContinueOnError)
	ctx := cli.NewContext(app, set, nil)
	ctx.Context = context.Background()

	require.NoError(t, opt.Action(ctx))

	reportDir := filepath.Join(cfg.Output.Dir, "detect", "memscan")
	pattern := filepath.Join(reportDir, "*-memscan-pid-"+strconv.Itoa(opt.Pid)+".json")
	reports, err := filepath.Glob(pattern)
	require.NoError(t, err)
	require.NotEmpty(t, reports)
	sort.Strings(reports)
	reportPath := reports[len(reports)-1]

	raw, err := os.ReadFile(reportPath)
	require.NoError(t, err)

	var report memscanReport
	require.NoError(t, json.Unmarshal(raw, &report))

	require.Equal(t, "detect memscan", report.Command)
	require.Equal(t, opt.Pid, report.Options.Pid)
	require.False(t, report.Options.All)
	require.True(t, report.Options.RWXOnly)
	require.Equal(t, uint64(memscanMaxBytesE2E), report.Options.MaxBytes)
	require.Equal(t, opt.Timeout.String(), report.Options.Timeout)
	require.True(t, report.Options.Evidence)
	require.Equal(t, uint64(1024), report.Options.EvidenceMaxBytes)

	require.Equal(t, backend.ModePortable, report.Backend.RequestedBackend)
	require.Equal(t, backend.ModePortable, report.Backend.EffectiveBackend)
	require.Equal(t, 1, report.Backend.RuleCount)

	require.Equal(t, 1, report.Summary.ProcessesScanned)
	require.Equal(t, 0, report.Summary.ProcessesSkipped)
	require.Equal(t, 1, report.Summary.DegradedProcesses)
	require.Greater(t, report.Summary.Matches, 0)
	require.Greater(t, report.Summary.EvidenceArtifacts, 0)

	require.Len(t, report.Processes, 1)
	proc := report.Processes[0]
	require.Equal(t, opt.Pid, proc.Pid)
	require.Equal(t, "scanned", proc.Status)
	require.NotNil(t, proc.Stats)
	require.True(t, proc.Stats.Degraded)
	require.Contains(t, proc.Stats.DegradedReasons, "max-bytes")
	require.NotEmpty(t, proc.Evidence)
	require.Equal(t, "hexdump", proc.Evidence[0].Kind)
	_, err = os.Stat(proc.Evidence[0].Path)
	require.NoError(t, err)

	found := false
	for _, match := range proc.Matches {
		if match.RuleName != memscanRuleNameE2E {
			continue
		}
		found = true
		require.Equal(t, opt.Pid, match.Pid)
		require.Contains(t, match.Tags, memscanRuleTagE2E)
		require.Equal(t, uint64(addr), match.Region.BaseAddress)
		require.Equal(t, uint32(pageExecuteReadWrite), match.Region.Protection)
		require.GreaterOrEqual(t, match.Region.Size, uint64(memscanRegionSizeE2E))
	}
	require.True(t, found)
}

func TestDetectMemscanWindowsAllHelperProcess(t *testing.T) {
	if os.Getenv(memscanAllHelperEnv) != "1" {
		t.Skip("helper process for TestDetectMemscanWindowsAllE2E")
	}

	addr, err := virtualAllocRWXE2E(memscanRegionSizeE2E)
	require.NoError(t, err)

	payload := []byte(memscanRuleNeedleE2E)
	dst := unsafe.Slice((*byte)(unsafe.Pointer(addr)), len(payload))
	copy(dst, payload)

	_, _ = fmt.Fprintf(os.Stdout, "READY pid=%d addr=0x%x\n", os.Getpid(), addr)
	time.Sleep(60 * time.Second)
}

func TestDetectMemscanWindowsAllE2E(t *testing.T) {
	if os.Getenv(memscanAllHelperEnv) == "1" {
		t.Skip("helper mode")
	}

	tmpDir := t.TempDir()

	prevCfg := internal.GetGlobalConfig()
	cfg := config.Default()
	cfg.Output.Dir = filepath.Join(tmpDir, "reports")
	internal.SetGlobalConfig(cfg)
	t.Cleanup(func() {
		internal.SetGlobalConfig(prevCfg)
	})

	ruleDir := filepath.Join(tmpDir, "rules")
	require.NoError(t, os.MkdirAll(ruleDir, 0o755))

	rulePath := filepath.Join(ruleDir, "memscan_all_e2e.yar")
	rule := `rule ` + memscanRuleNameE2E + ` : ` + memscanRuleTagE2E + ` test {
  strings:
    $a = "` + memscanRuleNeedleE2E + `"
  condition:
    $a
}
`
	require.NoError(t, os.WriteFile(rulePath, []byte(rule), 0o600))

	cmd := exec.Command(os.Args[0], "-test.run=TestDetectMemscanWindowsAllHelperProcess", "-test.count=1")
	cmd.Env = append(os.Environ(), memscanAllHelperEnv+"=1")
	stdout, err := cmd.StdoutPipe()
	require.NoError(t, err)
	cmd.Stderr = cmd.Stdout
	require.NoError(t, cmd.Start())
	t.Cleanup(func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		_ = cmd.Wait()
	})

	reader := bufio.NewReader(stdout)
	line, err := reader.ReadString('\n')
	require.NoError(t, err)
	require.Contains(t, line, "READY")

	helperPID := cmd.Process.Pid
	bogusPID := int32(2147483647)

	prevListProcessesFn := listProcessesFn
	listProcessesFn = func() ([]*process.Process, error) {
		return []*process.Process{
			{Pid: int32(helperPID)},
			{Pid: bogusPID},
		}, nil
	}
	t.Cleanup(func() {
		listProcessesFn = prevListProcessesFn
	})

	opt := NewDetectPluginYaraMemScan()
	opt.Pid = 0
	opt.All = true
	opt.RulePath = rulePath
	opt.Backend = string(backend.ModePortable)
	opt.RWXOnly = true
	opt.MaxBytes = 0
	opt.MaxRegions = 0
	opt.Timeout = 10 * time.Second

	app := cli.NewApp()
	set := flag.NewFlagSet("test", flag.ContinueOnError)
	ctx := cli.NewContext(app, set, nil)
	ctx.Context = context.Background()

	require.NoError(t, opt.Action(ctx))

	reportDir := filepath.Join(cfg.Output.Dir, "detect", "memscan")
	pattern := filepath.Join(reportDir, "*-memscan-all.json")
	reports, err := filepath.Glob(pattern)
	require.NoError(t, err)
	require.NotEmpty(t, reports)
	sort.Strings(reports)
	reportPath := reports[len(reports)-1]

	raw, err := os.ReadFile(reportPath)
	require.NoError(t, err)

	var report memscanReport
	require.NoError(t, json.Unmarshal(raw, &report))

	require.Equal(t, "detect memscan", report.Command)
	require.True(t, report.Options.All)
	require.Equal(t, backend.ModePortable, report.Backend.RequestedBackend)
	require.Equal(t, backend.ModePortable, report.Backend.EffectiveBackend)

	require.Equal(t, 2, report.Summary.TargetsSelected)
	require.Equal(t, 1, report.Summary.ProcessesScanned)
	require.Equal(t, 1, report.Summary.ProcessesSkipped)
	require.Equal(t, 1, report.Summary.SkippedReasons[string(memscan.ReadErrorInvalidParameter)])

	require.Len(t, report.Processes, 2)
	var skipped *memscanProcess
	for i := range report.Processes {
		if report.Processes[i].Status != "skipped" {
			continue
		}
		skipped = &report.Processes[i]
		break
	}
	require.NotNil(t, skipped)
	require.Equal(t, int(bogusPID), skipped.Pid)
	require.Equal(t, string(memscan.ReadErrorInvalidParameter), skipped.SkipReason)
	require.NotEmpty(t, skipped.Error)
}

func TestDetectMemscanWindowsMinidumpE2E(t *testing.T) {
	if os.Getenv(memscanMinidumpEnv) != "1" {
		t.Skip("minidump is opt-in because it produces sensitive artifacts")
	}

	tmpDir := t.TempDir()

	prevCfg := internal.GetGlobalConfig()
	cfg := config.Default()
	cfg.Output.Dir = filepath.Join(tmpDir, "reports")
	internal.SetGlobalConfig(cfg)
	t.Cleanup(func() {
		internal.SetGlobalConfig(prevCfg)
	})

	ruleDir := filepath.Join(tmpDir, "rules")
	require.NoError(t, os.MkdirAll(ruleDir, 0o755))

	rulePath := filepath.Join(ruleDir, "memscan_minidump_e2e.yar")
	rule := `rule ` + memscanRuleNameE2E + ` : ` + memscanRuleTagE2E + ` test {
  strings:
    $a = "` + memscanRuleNeedleE2E + `"
  condition:
    $a
}
`
	require.NoError(t, os.WriteFile(rulePath, []byte(rule), 0o600))

	addr, err := virtualAllocRWXE2E(memscanRegionSizeE2E)
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, virtualFreeE2E(addr))
	})

	payload := []byte(memscanRuleNeedleE2E)
	dst := unsafe.Slice((*byte)(unsafe.Pointer(addr)), len(payload))
	copy(dst, payload)

	opt := NewDetectPluginYaraMemScan()
	opt.Pid = os.Getpid()
	opt.All = false
	opt.RulePath = rulePath
	opt.Backend = string(backend.ModePortable)
	opt.RWXOnly = true
	opt.MaxBytes = memscanMaxBytesE2E
	opt.MaxRegions = 0
	opt.Timeout = 30 * time.Second
	opt.MiniDump = true
	opt.MiniDumpMaxProcesses = 1

	app := cli.NewApp()
	set := flag.NewFlagSet("test", flag.ContinueOnError)
	ctx := cli.NewContext(app, set, nil)
	ctx.Context = context.Background()

	require.NoError(t, opt.Action(ctx))

	reportDir := filepath.Join(cfg.Output.Dir, "detect", "memscan")
	pattern := filepath.Join(reportDir, "*-memscan-pid-"+strconv.Itoa(opt.Pid)+".json")
	reports, err := filepath.Glob(pattern)
	require.NoError(t, err)
	require.NotEmpty(t, reports)
	sort.Strings(reports)
	reportPath := reports[len(reports)-1]

	raw, err := os.ReadFile(reportPath)
	require.NoError(t, err)

	var report memscanReport
	require.NoError(t, json.Unmarshal(raw, &report))

	require.Equal(t, "detect memscan", report.Command)
	require.True(t, report.Options.MiniDump)
	require.Equal(t, 1, report.Options.MiniDumpMaxProcesses)
	require.Equal(t, 1, report.Summary.ProcessesScanned)
	require.Equal(t, 0, report.Summary.ProcessesSkipped)
	require.Greater(t, report.Summary.EvidenceArtifacts, 0)

	require.Len(t, report.Processes, 1)
	proc := report.Processes[0]
	foundDump := false
	for _, ev := range proc.Evidence {
		if ev.Kind != "minidump" {
			continue
		}
		foundDump = true
		fi, err := os.Stat(ev.Path)
		require.NoError(t, err)
		require.Greater(t, fi.Size(), int64(0))
	}
	require.True(t, foundDump)
}
