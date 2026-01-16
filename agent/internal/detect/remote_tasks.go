//go:build linux || windows || darwin

package detect

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/m-sec-org/d-eyes/agent/internal"
	"github.com/m-sec-org/d-eyes/agent/internal/detect/backend"
	"github.com/m-sec-org/d-eyes/agent/internal/detect/engine"
	"github.com/m-sec-org/d-eyes/agent/internal/detect/memscan"
	"github.com/m-sec-org/d-eyes/agent/internal/tasks"
	"github.com/m-sec-org/d-eyes/agent/pkg/exit"
	"github.com/m-sec-org/d-eyes/agent/pkg/reporting"
)

func init() {
	if err := internal.RegisterTaskRunner("detect.diag", remoteDetectDiagRunner{}); err != nil {
		panic(err)
	}
	if err := internal.RegisterTaskRunner("detect.memscan", remoteDetectMemscanRunner{}); err != nil {
		panic(err)
	}
}

type remoteDetectDiagRunner struct{}

func (remoteDetectDiagRunner) Run(ctx context.Context, req tasks.TaskRequest) (tasks.TaskResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	manager := req.Manager
	if manager == nil {
		manager = reporting.NewManager(req.Config)
	}
	rulePath := flagString(req.Flags, "rule", "")
	requested := resolveBackendMode(flagString(req.Flags, "backend", "auto"))
	result, err := backend.Load(backend.Options{
		RulePath: rulePath,
		Mode:     requested,
	})
	if err != nil {
		return tasks.TaskResult{}, err
	}
	snapshot := result.Manager.Snapshot()
	files := result.Manager.Sources()

	var analysis yaraDiagAnalysis
	if result.Backend == backend.ModeNative {
		analysis, err = analyzeSourcesNative(files)
		if err != nil {
			return tasks.TaskResult{}, err
		}
	} else {
		analysis = analyzeSourcesPortable(files)
	}

	out := yaraDiagOutput{
		RequestedBackend: requested,
		EffectiveBackend: result.Backend,
		Engine:           result.Bundle.Name(),
		RuleCount:        result.Bundle.RuleCount(),
		Version:          result.Bundle.Version(),
		Source:           snapshot.Source,
		CustomHash:       snapshot.CustomHash,
		LoadedAt:         snapshot.LoadedAt,
		Coverage:         result.Stats.Coverage(),
		Stats:            result.Stats.Clone(),
		Fallback:         result.Fallback,
		FallbackReason:   result.FallbackReason,
		NativeAvailable:  nativeDiagAvailable(),
		Analysis:         analysis,
		MissingFamilies:  computeMissingFamilies(analysis.Families),
	}

	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = "diag"
	} else {
		name = name + "-diag"
	}
	file, path, err := manager.CreateFile("detect/diag", name, "json")
	if err != nil {
		return tasks.TaskResult{}, err
	}
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(out); err != nil {
		_ = file.Close()
		return tasks.TaskResult{}, err
	}
	_ = file.Close()

	return tasks.TaskResult{
		Outputs: []reporting.OutputRecord{
			{Label: "诊断报告", Path: path},
		},
	}, nil
}

type remoteDetectMemscanRunner struct{}

const (
	memscanApprovalRequiredKey       = "memscan_approval_required"
	memscanApprovedKey               = "memscan_approved"
	memscanEvidenceApprovedKey       = "memscan_evidence_approved"
	memscanErrorCodeApprovalRequired = "detect.memscan.approval_required"
	memscanErrorCodeEvidenceRequired = "detect.memscan.evidence_approval_required"
)

func (remoteDetectMemscanRunner) Run(ctx context.Context, req tasks.TaskRequest) (tasks.TaskResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if runtime.GOOS != "windows" {
		return tasks.TaskResult{}, exit.New(1, fmt.Errorf("detect.memscan: %w", memscan.ErrUnsupportedPlatform))
	}

	opt := NewDetectPluginYaraMemScan()
	opt.Pid = flagInt(req.Flags, "pid", 0)
	opt.All = flagBool(req.Flags, "all", false)
	opt.RulePath = flagString(req.Flags, "rule", "")
	opt.Backend = flagString(req.Flags, "backend", "auto")
	opt.RWXOnly = flagBool(req.Flags, "rwx_only", opt.RWXOnly)
	opt.MaxBytes = flagUint64(req.Flags, "max_bytes", opt.MaxBytes)
	opt.MaxRegions = flagInt(req.Flags, "max_regions", opt.MaxRegions)
	opt.Evidence = flagBool(req.Flags, "evidence", false)
	opt.MiniDump = flagBool(req.Flags, "minidump", false)

	if timeout := selectMemscanTimeout(req); timeout > 0 {
		opt.Timeout = timeout
	}

	if errCode, err := validateMemscanApproval(req.Metadata, opt.Evidence || opt.MiniDump); err != nil {
		return tasks.TaskResult{
			Metadata: map[string]string{"error_code": errCode},
		}, exit.New(65, err)
	}

	if err := validateMemscanTargets(opt.Pid, opt.All); err != nil {
		return tasks.TaskResult{}, exit.New(64, err)
	}
	if opt.MaxRegions < 0 {
		return tasks.TaskResult{}, exit.New(64, errors.New("memscan: max_regions must be >= 0"))
	}
	if opt.Timeout < 0 {
		return tasks.TaskResult{}, exit.New(64, errors.New("memscan: timeout must be >= 0"))
	}

	start := time.Now()
	requestedBackend := resolveBackendMode(opt.Backend)
	result, err := backend.Load(backend.Options{
		RulePath: opt.RulePath,
		Mode:     requestedBackend,
	})
	if err != nil {
		return tasks.TaskResult{}, err
	}

	scanCtx := ctx
	var cancel context.CancelFunc
	if opt.Timeout > 0 {
		scanCtx, cancel = context.WithTimeout(ctx, opt.Timeout)
		defer cancel()
	}

	manager := req.Manager
	if manager == nil {
		manager = reporting.NewManager(req.Config)
	}

	targets, err := opt.resolveTargets()
	if err != nil {
		return tasks.TaskResult{}, err
	}

	report := memscanReport{
		Command:   "detect memscan",
		StartedAt: start.UTC(),
		Options: func() memscanReportOpts {
			out := memscanReportOpts{
				Pid:        opt.Pid,
				All:        opt.All,
				RulePath:   opt.RulePath,
				Backend:    requestedBackend,
				RWXOnly:    opt.RWXOnly,
				MaxBytes:   opt.MaxBytes,
				MaxRegions: opt.MaxRegions,
				Timeout:    opt.Timeout.String(),
			}
			if opt.Evidence {
				out.Evidence = true
				out.EvidenceMaxBytes = opt.EvidenceMaxBytes
				out.EvidenceContextBytes = opt.EvidenceContextBytes
				out.EvidenceMaxOffsets = opt.EvidenceMaxOffsets
				out.EvidenceMaxArtifacts = opt.EvidenceMaxArtifacts
				out.EvidenceMaxTotal = opt.EvidenceMaxTotal
				out.EvidenceMaxBytesPerProcess = opt.EvidenceMaxBytesPerProcess
				out.EvidenceMaxBytesTotal = opt.EvidenceMaxBytesTotal
			}
			if opt.MiniDump {
				out.MiniDump = true
				out.MiniDumpMaxProcesses = opt.MiniDumpMaxProcesses
			}
			return out
		}(),
		Backend: memscanBackend{
			RequestedBackend: requestedBackend,
			EffectiveBackend: result.Backend,
			Engine:           result.Bundle.Name(),
			Version:          result.Bundle.Version(),
			RuleCount:        result.Bundle.RuleCount(),
			Coverage:         result.Stats.Coverage(),
			Fallback:         result.Fallback,
			FallbackReason:   strings.TrimSpace(result.FallbackReason),
		},
		Summary: memscanSummary{
			TargetsSelected: len(targets),
			SkippedReasons:  make(map[string]int),
		},
	}

	riskCounts := make(map[string]int)
	hexdumpsWritten := 0
	hexdumpBytesWritten := uint64(0)
	minidumpsWritten := 0

	for _, p := range targets {
		if scanCtx.Err() != nil {
			break
		}
		if p == nil || p.Pid <= 0 {
			continue
		}
		pid := int(p.Pid)

		name, _ := p.Name()
		exe, _ := p.Exe()
		processEntry := memscanProcess{
			Pid:    pid,
			Name:   name,
			Exe:    exe,
			Status: "scanned",
		}

		scanProc, err := openMemscanProcessFn(pid)
		if err != nil {
			processEntry.Status = "skipped"
			processEntry.SkipReason = classifyProcessSkipReason(err)
			processEntry.Error = err.Error()
			report.Processes = append(report.Processes, processEntry)
			report.Summary.ProcessesSkipped++
			report.Summary.SkippedReasons[processEntry.SkipReason]++
			continue
		}

		func() {
			defer func() {
				_ = scanProc.Close()
			}()

			filter := memscan.FilterCommitted
			if opt.RWXOnly {
				filter = memscan.FilterRWX
			}
			scanOpts := memscan.Options{
				Filter:     filter,
				MaxBytes:   opt.MaxBytes,
				MaxRegions: opt.MaxRegions,
				Timeout:    0,
			}

			var matches []memscanMatch
			evidences := make([]memscanEvidence, 0)
			hexdumpAgg := make(map[hexdumpEvidenceKey]*hexdumpEvidenceAggregate, 16)
			hexdumpsWrittenInProcess := 0
			hexdumpBytesWrittenInProcess := uint64(0)
			stats, walkErr := scanProc.Walk(scanCtx, scanOpts, func(chunk memscan.Chunk) error {
				chunkMatches, err := result.Bundle.Scan(chunk.Data, engine.ScanOptions{
					FilePath: fmt.Sprintf("pid=%d addr=0x%x", pid, chunk.Address),
				})
				if err != nil {
					return memscanChunkScanError{cause: err}
				}
				for _, match := range chunkMatches {
					out := convertMemscanMatch(pid, name, chunk, match)
					matches = append(matches, out)
					level := normalizeRiskLevel(out.Risk.Level)
					if level != "" {
						riskCounts[level]++
					}
					if !opt.Evidence {
						continue
					}

					key := hexdumpEvidenceKey{
						Rule:          match.RuleName,
						RegionBase:    chunk.Region.Base,
						RegionSize:    chunk.Region.Size,
						RegionProtect: chunk.Region.Protect,
					}
					agg, exists := hexdumpAgg[key]
					if !exists {
						agg = &hexdumpEvidenceAggregate{evidenceIndex: -1}
						hexdumpAgg[key] = agg
					} else {
						report.Summary.HexdumpEvidenceDeduped++
					}
					agg.offsets.add(chunk, match, opt.EvidenceMaxOffsets)
					if exists {
						continue
					}

					if opt.EvidenceMaxArtifacts > 0 && hexdumpsWrittenInProcess >= opt.EvidenceMaxArtifacts {
						report.Summary.HexdumpEvidenceSkippedByLimit++
						continue
					}
					if opt.EvidenceMaxTotal > 0 && hexdumpsWritten >= opt.EvidenceMaxTotal {
						report.Summary.HexdumpEvidenceSkippedByLimit++
						continue
					}

					plannedBytes, err := plannedMemscanHexdumpBytes(chunk, match, opt)
					if err != nil {
						report.Summary.HexdumpEvidenceErrors++
						processEntry.Notes = append(processEntry.Notes, fmt.Sprintf("evidence error(rule=%s): %v", match.RuleName, err))
						continue
					}
					if opt.EvidenceMaxBytesPerProcess > 0 && hexdumpBytesWrittenInProcess+plannedBytes > opt.EvidenceMaxBytesPerProcess {
						report.Summary.HexdumpEvidenceSkippedByBytesLimit++
						continue
					}
					if opt.EvidenceMaxBytesTotal > 0 && hexdumpBytesWritten+plannedBytes > opt.EvidenceMaxBytesTotal {
						report.Summary.HexdumpEvidenceSkippedByBytesLimit++
						continue
					}

					ev, err := writeMemscanHexdumpEvidence(manager, pid, name, chunk, match, opt)
					if err != nil {
						report.Summary.HexdumpEvidenceErrors++
						processEntry.Notes = append(processEntry.Notes, fmt.Sprintf("evidence error(rule=%s): %v", match.RuleName, err))
						continue
					}

					report.Summary.HexdumpEvidenceArtifacts++
					report.Summary.HexdumpEvidenceBytes += ev.Bytes
					hexdumpBytesWrittenInProcess += ev.Bytes
					hexdumpBytesWritten += ev.Bytes

					agg.evidenceIndex = len(evidences)
					evidences = append(evidences, ev)
					hexdumpsWrittenInProcess++
					hexdumpsWritten++
				}
				return nil
			})

			processEntry.Matches = matches
			for _, agg := range hexdumpAgg {
				if agg == nil || agg.evidenceIndex < 0 || agg.evidenceIndex >= len(evidences) {
					continue
				}
				evidences[agg.evidenceIndex].OffsetSummary = agg.offsets.summary()
			}
			processEntry.Evidence = evidences
			statsOut := memscanStatsFrom(stats)
			processEntry.Stats = &statsOut

			if walkErr != nil {
				processEntry.Status = "partial"
				processEntry.Error = walkErr.Error()
			}
			if statsOut.Degraded {
				report.Summary.DegradedProcesses++
			}
			report.Summary.Matches += len(matches)
		}()

		if opt.MiniDump && len(processEntry.Matches) > 0 {
			report.Summary.MiniDumpEligible++
			if opt.MiniDumpMaxProcesses > 0 && minidumpsWritten >= opt.MiniDumpMaxProcesses {
				report.Summary.MiniDumpSkippedByLimit++
				processEntry.MiniDump = &memscanMiniDump{
					Status:    "skipped",
					ErrorKind: "limit",
					Error:     fmt.Sprintf("minidump-max-processes=%d reached", opt.MiniDumpMaxProcesses),
				}
			} else {
				report.Summary.MiniDumpAttempts++
				ev, err := writeMemscanMiniDumpEvidence(manager, pid)
				if err != nil {
					kind := classifyMiniDumpError(err)
					if kind == "" {
						kind = "other"
					}
					report.Summary.MiniDumpFailed++
					if report.Summary.MiniDumpFailedByKind == nil {
						report.Summary.MiniDumpFailedByKind = make(map[string]int, 4)
					}
					report.Summary.MiniDumpFailedByKind[kind]++
					processEntry.MiniDump = &memscanMiniDump{
						Status:    "failed",
						ErrorKind: kind,
						Error:     err.Error(),
					}
					processEntry.Notes = append(processEntry.Notes, fmt.Sprintf("minidump failed(%s): %v", kind, err))
				} else {
					report.Summary.MiniDumpWritten++
					processEntry.MiniDump = &memscanMiniDump{
						Status: "written",
						Path:   ev.Path,
						Bytes:  ev.Bytes,
					}
					processEntry.Evidence = append(processEntry.Evidence, ev)
					minidumpsWritten++
				}
			}
		}
		if len(processEntry.Evidence) > 0 {
			report.Summary.EvidenceArtifacts += len(processEntry.Evidence)
		}
		report.Processes = append(report.Processes, processEntry)
		report.Summary.ProcessesScanned++
	}

	report.FinishedAt = time.Now().UTC()
	report.Duration = time.Since(start).String()

	fileName := "memscan"
	if opt.All {
		fileName = "memscan-all"
	} else if opt.Pid > 0 {
		fileName = fmt.Sprintf("memscan-pid-%d", opt.Pid)
	}
	if reqName := strings.TrimSpace(req.Name); reqName != "" {
		fileName = reqName + "-" + fileName
	}
	f, path, err := manager.CreateFile("detect/memscan", fileName, "json")
	if err != nil {
		return tasks.TaskResult{}, err
	}
	if err := writeMemscanReport(f, report); err != nil {
		_ = f.Close()
		return tasks.TaskResult{}, err
	}
	_ = f.Close()

	notes := make([]string, 0)
	if scanCtx.Err() != nil && errors.Is(scanCtx.Err(), context.DeadlineExceeded) {
		notes = append(notes, fmt.Sprintf("timeout reached: %s", opt.Timeout))
	}
	if report.Summary.ProcessesSkipped > 0 {
		notes = append(notes, fmt.Sprintf("processes skipped: %d", report.Summary.ProcessesSkipped))
	}
	if report.Summary.DegradedProcesses > 0 {
		notes = append(notes, fmt.Sprintf("degraded processes: %d", report.Summary.DegradedProcesses))
	}
	if report.Summary.EvidenceArtifacts > 0 {
		notes = append(notes, fmt.Sprintf("evidence artifacts: %d (sensitive)", report.Summary.EvidenceArtifacts))
	}
	if report.Summary.HexdumpEvidenceDeduped > 0 {
		notes = append(notes, fmt.Sprintf("evidence deduped: %d", report.Summary.HexdumpEvidenceDeduped))
	}
	if report.Summary.HexdumpEvidenceSkippedByLimit > 0 {
		notes = append(notes, fmt.Sprintf("evidence skipped by count limit: %d", report.Summary.HexdumpEvidenceSkippedByLimit))
	}
	if report.Summary.HexdumpEvidenceSkippedByBytesLimit > 0 {
		notes = append(notes, fmt.Sprintf("evidence skipped by bytes limit: %d", report.Summary.HexdumpEvidenceSkippedByBytesLimit))
	}
	if report.Summary.HexdumpEvidenceBytes > 0 {
		notes = append(notes, fmt.Sprintf("evidence raw bytes: %d", report.Summary.HexdumpEvidenceBytes))
	}
	if report.Summary.MiniDumpFailed > 0 {
		notes = append(notes, fmt.Sprintf("minidump failed: %d", report.Summary.MiniDumpFailed))
	}
	if report.Summary.MiniDumpSkippedByLimit > 0 {
		notes = append(notes, fmt.Sprintf("minidump skipped by limit: %d", report.Summary.MiniDumpSkippedByLimit))
	}

	outputs := []reporting.OutputRecord{
		{Label: "内存扫描报告", Path: path},
	}
	if report.Summary.EvidenceArtifacts > 0 {
		evidenceDir := filepath.Join(manager.BaseDir(), "detect", "memscan", "evidence")
		outputs = append(outputs, reporting.OutputRecord{Label: "证据保全目录", Path: evidenceDir})
	}

	return tasks.TaskResult{
		Outputs: outputs,
		Risks:   riskCounts,
		Notes:   notes,
	}, nil
}

func validateMemscanApproval(meta map[string]string, evidenceRequested bool) (string, error) {
	if !metaValueTrue(meta, memscanApprovalRequiredKey) || !metaValueTrue(meta, memscanApprovedKey) {
		return memscanErrorCodeApprovalRequired, fmt.Errorf("memscan requires approval metadata: %s=true and %s=true", memscanApprovalRequiredKey, memscanApprovedKey)
	}
	if evidenceRequested && !metaValueTrue(meta, memscanEvidenceApprovedKey) {
		return memscanErrorCodeEvidenceRequired, fmt.Errorf("memscan evidence/minidump requires approval metadata: %s=true", memscanEvidenceApprovedKey)
	}
	return "", nil
}

func metaValueTrue(meta map[string]string, key string) bool {
	if meta == nil {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(meta[key]), "true")
}

func selectMemscanTimeout(req tasks.TaskRequest) time.Duration {
	timeout := req.Timeout
	if timeout <= 0 {
		return 0
	}
	if req.Config.Performance.Timeout > 0 && timeout == req.Config.Performance.Timeout {
		return 0
	}
	return timeout
}

func flagString(flags map[string]any, key, fallback string) string {
	if flags == nil {
		return fallback
	}
	raw, ok := flags[key]
	if !ok || raw == nil {
		return fallback
	}
	switch v := raw.(type) {
	case string:
		if s := strings.TrimSpace(v); s != "" {
			return s
		}
	case []byte:
		if s := strings.TrimSpace(string(v)); s != "" {
			return s
		}
	case fmt.Stringer:
		if s := strings.TrimSpace(v.String()); s != "" {
			return s
		}
	}
	return fallback
}

func flagBool(flags map[string]any, key string, fallback bool) bool {
	if flags == nil {
		return fallback
	}
	raw, ok := flags[key]
	if !ok || raw == nil {
		return fallback
	}
	switch v := raw.(type) {
	case bool:
		return v
	case string:
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "true", "1", "yes", "y", "on":
			return true
		case "false", "0", "no", "n", "off":
			return false
		}
	}
	return fallback
}

func flagInt(flags map[string]any, key string, fallback int) int {
	value, ok := flagInt64(flags, key)
	if !ok {
		return fallback
	}
	if value > int64(math.MaxInt) || value < int64(math.MinInt) {
		return fallback
	}
	return int(value)
}

func flagUint64(flags map[string]any, key string, fallback uint64) uint64 {
	value, ok := flagInt64(flags, key)
	if !ok || value < 0 {
		return fallback
	}
	return uint64(value)
}

func flagInt64(flags map[string]any, key string) (int64, bool) {
	if flags == nil {
		return 0, false
	}
	raw, ok := flags[key]
	if !ok || raw == nil {
		return 0, false
	}
	switch v := raw.(type) {
	case int:
		return int64(v), true
	case int32:
		return int64(v), true
	case int64:
		return v, true
	case uint:
		if v > uint(math.MaxInt64) {
			return 0, false
		}
		return int64(v), true
	case uint32:
		return int64(v), true
	case uint64:
		if v > uint64(math.MaxInt64) {
			return 0, false
		}
		return int64(v), true
	case float64:
		if math.IsNaN(v) || math.IsInf(v, 0) {
			return 0, false
		}
		if v != math.Trunc(v) {
			return 0, false
		}
		if v > float64(math.MaxInt64) || v < float64(math.MinInt64) {
			return 0, false
		}
		return int64(v), true
	case json.Number:
		i, err := v.Int64()
		if err != nil {
			return 0, false
		}
		return i, true
	case string:
		s := strings.TrimSpace(v)
		if s == "" {
			return 0, false
		}
		if i, err := strconv.ParseInt(s, 10, 64); err == nil {
			return i, true
		}
	}
	return 0, false
}
