package tasks

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/m-sec-org/d-eyes/agent/internal/benchmark"
	"github.com/m-sec-org/d-eyes/agent/internal/benchmarkexec"
	"github.com/m-sec-org/d-eyes/agent/internal/sandbox"
	telemetrypkg "github.com/m-sec-org/d-eyes/agent/internal/telemetry"
	"github.com/m-sec-org/d-eyes/agent/pkg/config"
	"github.com/m-sec-org/d-eyes/agent/pkg/reporting"
	"github.com/m-sec-org/d-eyes/agent/pkg/threatintel"
)

type threatIntelReport struct {
	Findings []threatintel.Finding `json:"findings"`
	Metadata map[string]string     `json:"metadata"`
}

func TestThreatIntelMetadataPersistenceBaseline(t *testing.T) {
	t.Run("remote_ok", func(t *testing.T) {
		server, calls := newOpenTIPTestServer(t, http.StatusOK)
		cfg := testThreatIntelHybridConfig(t, server.URL, "super-secret")

		exec := &fakeBaselineExecutor{
			result: benchmarkexec.Result{
				Checks: []benchmark.CheckResult{{
					ID:          "C-1",
					Severity:    benchmark.SeverityHigh,
					ActualValue:  "sha256=" + strings.Repeat("deadbeef", 8),
					Name:        "hash check",
					Description: "for ti",
				}},
				SeverityCount: map[string]int{"high": 1},
				Duration:      10 * time.Millisecond,
			},
		}
		runner := BaselineRunnerWithExecutor(exec)

		req := TaskRequest{
			Config: cfg,
			Flags:  map[string]any{"scope": "os"},
			Quiet:  true,
		}
		req.ApplyDefaults("baseline")

		execMeta, report := runTaskAndLoadThreatIntelReport(t, "baseline", runner, req)
		require.GreaterOrEqual(t, atomic.LoadInt32(calls), int32(1))
		assertThreatIntelMetadataConsistent(t, execMeta, report.Metadata)
		require.Equal(t, "hybrid", execMeta["threatintel.mode_requested"])
		require.Equal(t, "hybrid", execMeta["threatintel.mode_effective"])
		require.Equal(t, "true", execMeta["threatintel.remote_enabled"])
		require.True(t, hasFindingSource(report.Findings, "opentip"))
	})

	t.Run("remote_quota_paused", func(t *testing.T) {
		server, calls := newOpenTIPTestServer(t, http.StatusTooManyRequests)
		cfg := testThreatIntelHybridConfig(t, server.URL, "super-secret")

		exec := &fakeBaselineExecutor{
			result: benchmarkexec.Result{
				Checks: []benchmark.CheckResult{{
					ID:          "C-1",
					Severity:    benchmark.SeverityHigh,
					ActualValue:  "sha256=" + strings.Repeat("deadbeef", 8),
					Name:        "hash check",
					Description: "for ti",
				}},
				SeverityCount: map[string]int{"high": 1},
				Duration:      10 * time.Millisecond,
			},
		}
		runner := BaselineRunnerWithExecutor(exec)

		req := TaskRequest{
			Config: cfg,
			Flags:  map[string]any{"scope": "os"},
			Quiet:  true,
		}
		req.ApplyDefaults("baseline")

		execMeta, report := runTaskAndLoadThreatIntelReport(t, "baseline", runner, req)
		require.GreaterOrEqual(t, atomic.LoadInt32(calls), int32(1))
		assertThreatIntelMetadataConsistent(t, execMeta, report.Metadata)
		require.Equal(t, "hybrid", execMeta["threatintel.mode_requested"])
		require.Equal(t, "local", execMeta["threatintel.mode_effective"])
		require.Equal(t, "false", execMeta["threatintel.remote_enabled"])
		require.Equal(t, "remote_paused,remote_quota_exceeded", execMeta["threatintel.notice"])
		require.Contains(t, execMeta["threatintel.notice_detail"], "provider=opentip")
		require.Contains(t, execMeta["threatintel.notice_detail"], "status=429")
		require.NotContains(t, execMeta["threatintel.notice_detail"], "super-secret")
	})
}

func TestThreatIntelMetadataPersistenceBAS(t *testing.T) {
	t.Run("remote_ok", func(t *testing.T) {
		server, calls := newOpenTIPTestServer(t, http.StatusOK)
		cfg := testThreatIntelHybridConfig(t, server.URL, "super-secret")
		runner := BASRunnerWithDeps(staticScenarioLoader{scenario: testScenarioWithHashOutput()}, staticSandboxFactory{}, staticTelemetryEncoder{})

		req := TaskRequest{
			Config: cfg,
			Flags:  map[string]any{"scenario-id": "test"},
			Quiet:  true,
		}
		req.ApplyDefaults("bas")

		execMeta, report := runTaskAndLoadThreatIntelReport(t, "bas", runner, req)
		require.GreaterOrEqual(t, atomic.LoadInt32(calls), int32(1))
		assertThreatIntelMetadataConsistent(t, execMeta, report.Metadata)
		require.Equal(t, "hybrid", execMeta["threatintel.mode_effective"])
		require.True(t, hasFindingSource(report.Findings, "opentip"))
	})

	t.Run("remote_quota_paused", func(t *testing.T) {
		server, calls := newOpenTIPTestServer(t, http.StatusTooManyRequests)
		cfg := testThreatIntelHybridConfig(t, server.URL, "super-secret")
		runner := BASRunnerWithDeps(staticScenarioLoader{scenario: testScenarioWithHashOutput()}, staticSandboxFactory{}, staticTelemetryEncoder{})

		req := TaskRequest{
			Config: cfg,
			Flags:  map[string]any{"scenario-id": "test"},
			Quiet:  true,
		}
		req.ApplyDefaults("bas")

		execMeta, report := runTaskAndLoadThreatIntelReport(t, "bas", runner, req)
		require.GreaterOrEqual(t, atomic.LoadInt32(calls), int32(1))
		assertThreatIntelMetadataConsistent(t, execMeta, report.Metadata)
		require.Equal(t, "local", execMeta["threatintel.mode_effective"])
		require.Equal(t, "remote_paused,remote_quota_exceeded", execMeta["threatintel.notice"])
	})
}

func TestThreatIntelMetadataPersistenceRespond(t *testing.T) {
	t.Run("remote_ok", func(t *testing.T) {
		server, calls := newOpenTIPTestServer(t, http.StatusOK)
		cfg := testThreatIntelHybridConfig(t, server.URL, "super-secret")
		cfg.Output.Dir = t.TempDir()

		target := t.TempDir()
		createTestFile(t, target, "sample.exe")
		req := TaskRequest{
			Config:  cfg,
			Flags:   map[string]any{"targets": target},
			Quiet:   true,
			Profile: "ransomware",
		}
		req.ApplyDefaults("respond")

		runner := RespondRunnerWithSelector(func(profile string) []respondModule {
			return []respondModule{{Name: "FileScan", Run: runFileScan}}
		})

		execMeta, report := runTaskAndLoadThreatIntelReport(t, "respond", runner, req)
		require.GreaterOrEqual(t, atomic.LoadInt32(calls), int32(1))
		assertThreatIntelMetadataConsistent(t, execMeta, report.Metadata)
		require.Equal(t, "hybrid", execMeta["threatintel.mode_effective"])
		require.True(t, hasFindingSource(report.Findings, "opentip"))
	})

	t.Run("remote_quota_paused", func(t *testing.T) {
		server, calls := newOpenTIPTestServer(t, http.StatusTooManyRequests)
		cfg := testThreatIntelHybridConfig(t, server.URL, "super-secret")
		cfg.Output.Dir = t.TempDir()

		target := t.TempDir()
		createTestFile(t, target, "sample.exe")
		req := TaskRequest{
			Config:  cfg,
			Flags:   map[string]any{"targets": target},
			Quiet:   true,
			Profile: "ransomware",
		}
		req.ApplyDefaults("respond")

		runner := RespondRunnerWithSelector(func(profile string) []respondModule {
			return []respondModule{{Name: "FileScan", Run: runFileScan}}
		})

		execMeta, report := runTaskAndLoadThreatIntelReport(t, "respond", runner, req)
		require.GreaterOrEqual(t, atomic.LoadInt32(calls), int32(1))
		assertThreatIntelMetadataConsistent(t, execMeta, report.Metadata)
		require.Equal(t, "local", execMeta["threatintel.mode_effective"])
		require.Equal(t, "remote_paused,remote_quota_exceeded", execMeta["threatintel.notice"])
	})
}

func newOpenTIPTestServer(t *testing.T, status int) (*httptest.Server, *int32) {
	t.Helper()
	var calls int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		switch r.URL.Path {
		case "/search/hash":
			if status == http.StatusTooManyRequests {
				w.Header().Set("Retry-After", "60")
				w.WriteHeader(http.StatusTooManyRequests)
				_, _ = w.Write([]byte(`{"error":"rate_limited"}`))
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"verdict":"malicious","confidence":"high"}`))
			return
		case "/scan/file":
			if status == http.StatusTooManyRequests {
				w.Header().Set("Retry-After", "60")
				w.WriteHeader(http.StatusTooManyRequests)
				_, _ = w.Write([]byte(`{"error":"rate_limited"}`))
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"verdict":"malicious","confidence":"high"}`))
			return
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	t.Cleanup(server.Close)
	return server, &calls
}

func testThreatIntelHybridConfig(t *testing.T, baseURL string, apiKey string) config.Config {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	cfg := config.Default()
	cfg.Output.Dir = t.TempDir()
	cfg.ThreatIntel.Mode = threatintel.ModeHybrid
	cfg.ThreatIntel.OpenTIPAPIKey = apiKey
	cfg.ThreatIntel.OpenTIPBaseURL = baseURL
	cfg.ThreatIntel.HTTPTimeout = 2 * time.Second
	return cfg
}

func runTaskAndLoadThreatIntelReport(t *testing.T, command string, runner TaskRunner, req TaskRequest) (map[string]string, threatIntelReport) {
	t.Helper()
	manager := reporting.NewManager(req.Config)
	summary, result, err := ExecuteWithResult(context.Background(), command, runner, req, manager)
	require.NoError(t, err)
	execModel := ToExecutionResult(summary, result, nil)

	tiPath := findThreatIntelReportPath(t, result.Outputs)
	report := readThreatIntelReport(t, tiPath)
	return execModel.Metadata, report
}

func findThreatIntelReportPath(t *testing.T, outputs []reporting.OutputRecord) string {
	t.Helper()
	for _, out := range outputs {
		if strings.Contains(out.Label, "威胁情报") {
			return out.Path
		}
	}
	require.Fail(t, "threatintel report output not found")
	return ""
}

func readThreatIntelReport(t *testing.T, path string) threatIntelReport {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	var report threatIntelReport
	require.NoError(t, json.Unmarshal(data, &report))
	return report
}

func assertThreatIntelMetadataConsistent(t *testing.T, execMeta, reportMeta map[string]string) {
	t.Helper()
	keys := []string{
		"threatintel.mode_requested",
		"threatintel.mode_effective",
		"threatintel.remote_configured",
		"threatintel.remote_enabled",
		"threatintel.remote_sources",
		"threatintel.notice",
		"threatintel.notice_detail",
	}
	for _, key := range keys {
		require.Contains(t, execMeta, key)
		require.Contains(t, reportMeta, key)
		require.Equal(t, execMeta[key], reportMeta[key], "metadata mismatch: %s", key)
	}
}

func hasFindingSource(findings []threatintel.Finding, source string) bool {
	for _, finding := range findings {
		if finding.Source == source {
			return true
		}
	}
	return false
}

type staticScenarioLoader struct {
	scenario Scenario
	err      error
}

func (s staticScenarioLoader) Load(_ TaskRequest) (Scenario, error) {
	if s.err != nil {
		return Scenario{}, s.err
	}
	return s.scenario, nil
}

type staticSandboxFactory struct{}

func (staticSandboxFactory) New(_ sandbox.Config, enabled bool) sandboxExecutor {
	return staticSandboxExecutor{enabled: enabled}
}

type staticSandboxExecutor struct {
	enabled bool
}

func (e staticSandboxExecutor) Execute(_ context.Context, _ Scenario, step ScenarioStep, _ bool) stepOutcome {
	now := time.Now().UTC()
	return stepOutcome{
		ID:        step.ID,
		Name:      step.Name,
		Status:    "succeeded",
		ExitCode:  0,
		StartedAt: now,
		EndedAt:   now,
		Stdout:    "sha256=" + strings.Repeat("deadbeef", 8),
		Sandbox:   enabled(e.enabled, step.UseSandbox),
		Sandboxed: false,
		Fallback:  false,
	}
}

func enabled(global bool, requested bool) bool {
	if !global {
		return false
	}
	return requested
}

type staticTelemetryEncoder struct{}

func (staticTelemetryEncoder) BuildSteps(_ Scenario, _ []stepOutcome) ([]telemetrypkg.BAStepTelemetry, int, int) {
	return nil, 0, 0
}

func (staticTelemetryEncoder) EncodeSteps(_ []telemetrypkg.BAStepTelemetry) (string, error) {
	return "", nil
}

func (staticTelemetryEncoder) EncodeStats(_ telemetrypkg.SandboxStats) (string, error) {
	return "", nil
}

func testScenarioWithHashOutput() Scenario {
	return Scenario{
		ID:   "test-scenario",
		Name: "Test Scenario",
		Steps: []ScenarioStep{
			{ID: "step-1", Name: "Step 1", UseSandbox: false},
		},
	}
}
