//go:build linux || windows || darwin

package detect

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v4/process"
	"github.com/urfave/cli/v2"

	"github.com/m-sec-org/d-eyes/agent/internal"
	"github.com/m-sec-org/d-eyes/agent/internal/detect/backend"
	"github.com/m-sec-org/d-eyes/agent/internal/detect/engine"
	"github.com/m-sec-org/d-eyes/agent/internal/detect/memscan"
	"github.com/m-sec-org/d-eyes/agent/internal/detect/scoring"
	"github.com/m-sec-org/d-eyes/agent/pkg/color"
	"github.com/m-sec-org/d-eyes/agent/pkg/reporting"
)

var YaraMemScanOption *YaraMemScanOptions

var (
	listProcessesFn      = process.Processes
	openMemscanProcessFn = memscan.Open
)

func init() {
	YaraMemScanOption = NewDetectPluginYaraMemScan()
	internal.RegisterDetectSubcommands(YaraMemScanOption)
}

type YaraMemScanOptions struct {
	Pid                        int
	All                        bool
	RulePath                   string
	Backend                    string
	RWXOnly                    bool
	MaxBytes                   uint64
	MaxRegions                 int
	Timeout                    time.Duration
	Evidence                   bool
	EvidenceMaxBytes           uint64
	EvidenceContextBytes       int
	EvidenceMaxOffsets         int
	EvidenceMaxArtifacts       int
	EvidenceMaxTotal           int
	EvidenceMaxBytesPerProcess uint64
	EvidenceMaxBytesTotal      uint64
	MiniDump                   bool
	MiniDumpMaxProcesses       int
	internal.BaseOption
}

func NewDetectPluginYaraMemScan() *YaraMemScanOptions {
	return &YaraMemScanOptions{
		RWXOnly:                    true,
		MaxBytes:                   32 * 1024 * 1024,
		MaxRegions:                 128,
		Timeout:                    2 * time.Minute,
		Evidence:                   false,
		EvidenceMaxBytes:           4 * 1024,
		EvidenceContextBytes:       256,
		EvidenceMaxOffsets:         128,
		EvidenceMaxArtifacts:       8,
		EvidenceMaxTotal:           64,
		EvidenceMaxBytesPerProcess: 32 * 1024,
		EvidenceMaxBytesTotal:      256 * 1024,
		MiniDump:                   false,
		MiniDumpMaxProcesses:       1,
		BaseOption: internal.BaseOption{
			Name:        "yara memscan",
			Author:      "msec",
			Description: "Scan Windows process memory regions with YARA rules and output a structured report",
		},
	}
}

func (opt *YaraMemScanOptions) InitCommand() []*cli.Command {
	return []*cli.Command{
		{
			Name:    "memscan",
			Usage:   "Scan Windows process memory (RWX-focused by default) with YARA rules",
			Aliases: []string{"ms"},
			Action:  opt.Action,
			Flags: []cli.Flag{
				&cli.IntFlag{
					Name:        "pid",
					Usage:       "Target PID to scan (must be used with --pid or --all)",
					Destination: &YaraMemScanOption.Pid,
				},
				&cli.BoolFlag{
					Name:        "all",
					Usage:       "Scan all processes (must be used with --pid or --all)",
					Destination: &YaraMemScanOption.All,
					Value:       false,
				},
				&cli.StringFlag{
					Name:        "rule",
					Aliases:     []string{"r"},
					Usage:       "Custom rule file or directory (defaults to embedded set)",
					Destination: &YaraMemScanOption.RulePath,
				},
				&cli.StringFlag{
					Name:        "backend",
					Usage:       "YARA backend (auto|native|portable). Defaults to env D_EYES_YARA_BACKEND or auto.",
					Destination: &YaraMemScanOption.Backend,
				},
				&cli.BoolFlag{
					Name:        "rwx-only",
					Usage:       "Only scan committed RWX regions (default true). When false, scan all committed readable regions (still skips guard/noaccess).",
					Destination: &YaraMemScanOption.RWXOnly,
					Value:       true,
				},
				&cli.Uint64Flag{
					Name:        "max-bytes",
					Usage:       "Max bytes to read per process (0 means unlimited, default 32MiB)",
					Destination: &YaraMemScanOption.MaxBytes,
					Value:       32 * 1024 * 1024,
				},
				&cli.IntFlag{
					Name:        "max-regions",
					Usage:       "Max matched regions per process (0 means unlimited, default 128)",
					Destination: &YaraMemScanOption.MaxRegions,
					Value:       128,
				},
				&cli.DurationFlag{
					Name:        "timeout",
					Usage:       "Global scan timeout (0 means unlimited, default 2m)",
					Destination: &YaraMemScanOption.Timeout,
					Value:       2 * time.Minute,
				},
				&cli.BoolFlag{
					Name:        "evidence",
					Usage:       "Write hexdump evidence for matched chunks (sensitive; default false)",
					Destination: &YaraMemScanOption.Evidence,
					Value:       false,
				},
				&cli.Uint64Flag{
					Name:        "evidence-max-bytes",
					Usage:       "Max bytes per hexdump evidence artifact (0 means unlimited, default 4096)",
					Destination: &YaraMemScanOption.EvidenceMaxBytes,
					Value:       4 * 1024,
				},
				&cli.IntFlag{
					Name:        "evidence-context-bytes",
					Usage:       "Bytes of context before the first match offset (default 256)",
					Destination: &YaraMemScanOption.EvidenceContextBytes,
					Value:       256,
				},
				&cli.IntFlag{
					Name:        "evidence-max-offsets",
					Usage:       "Max captured offsets stored in report per hexdump evidence (0 means unlimited, default 128)",
					Destination: &YaraMemScanOption.EvidenceMaxOffsets,
					Value:       128,
				},
				&cli.IntFlag{
					Name:        "evidence-max-artifacts",
					Usage:       "Max evidence artifacts per process (0 means unlimited, default 8)",
					Destination: &YaraMemScanOption.EvidenceMaxArtifacts,
					Value:       8,
				},
				&cli.IntFlag{
					Name:        "evidence-max-total",
					Usage:       "Max hexdump evidence artifacts across all processes (0 means unlimited, default 64)",
					Destination: &YaraMemScanOption.EvidenceMaxTotal,
					Value:       64,
				},
				&cli.Uint64Flag{
					Name:        "evidence-max-bytes-per-process",
					Usage:       "Max hexdump evidence raw bytes per process (0 means unlimited, default 32768)",
					Destination: &YaraMemScanOption.EvidenceMaxBytesPerProcess,
					Value:       32 * 1024,
				},
				&cli.Uint64Flag{
					Name:        "evidence-max-bytes-total",
					Usage:       "Max hexdump evidence raw bytes across all processes (0 means unlimited, default 262144)",
					Destination: &YaraMemScanOption.EvidenceMaxBytesTotal,
					Value:       256 * 1024,
				},
				&cli.BoolFlag{
					Name:        "minidump",
					Usage:       "Generate a Windows process minidump for matched processes (highly sensitive; default false)",
					Destination: &YaraMemScanOption.MiniDump,
					Value:       false,
				},
				&cli.IntFlag{
					Name:        "minidump-max-processes",
					Usage:       "Max processes to generate minidumps for (0 means unlimited, default 1)",
					Destination: &YaraMemScanOption.MiniDumpMaxProcesses,
					Value:       1,
				},
			},
		},
	}
}

type memscanReport struct {
	Command    string            `json:"command"`
	StartedAt  time.Time         `json:"started_at"`
	FinishedAt time.Time         `json:"finished_at"`
	Duration   string            `json:"duration"`
	Options    memscanReportOpts `json:"options"`
	Backend    memscanBackend    `json:"backend"`
	Summary    memscanSummary    `json:"summary"`
	Processes  []memscanProcess  `json:"processes"`
}

type memscanReportOpts struct {
	Pid                        int          `json:"pid,omitempty"`
	All                        bool         `json:"all"`
	RulePath                   string       `json:"rule_path,omitempty"`
	Backend                    backend.Mode `json:"backend"`
	RWXOnly                    bool         `json:"rwx_only"`
	MaxBytes                   uint64       `json:"max_bytes"`
	MaxRegions                 int          `json:"max_regions"`
	Timeout                    string       `json:"timeout"`
	Evidence                   bool         `json:"evidence,omitempty"`
	EvidenceMaxBytes           uint64       `json:"evidence_max_bytes,omitempty"`
	EvidenceContextBytes       int          `json:"evidence_context_bytes,omitempty"`
	EvidenceMaxOffsets         int          `json:"evidence_max_offsets,omitempty"`
	EvidenceMaxArtifacts       int          `json:"evidence_max_artifacts,omitempty"`
	EvidenceMaxTotal           int          `json:"evidence_max_total,omitempty"`
	EvidenceMaxBytesPerProcess uint64       `json:"evidence_max_bytes_per_process,omitempty"`
	EvidenceMaxBytesTotal      uint64       `json:"evidence_max_bytes_total,omitempty"`
	MiniDump                   bool         `json:"minidump,omitempty"`
	MiniDumpMaxProcesses       int          `json:"minidump_max_processes,omitempty"`
}

type memscanBackend struct {
	RequestedBackend backend.Mode `json:"requested_backend"`
	EffectiveBackend backend.Mode `json:"effective_backend"`
	Engine           string       `json:"engine"`
	Version          string       `json:"version"`
	RuleCount        int          `json:"rule_count"`
	Coverage         float64      `json:"coverage"`
	Fallback         bool         `json:"fallback"`
	FallbackReason   string       `json:"fallback_reason,omitempty"`
}

type memscanSummary struct {
	TargetsSelected                    int            `json:"targets_selected"`
	ProcessesScanned                   int            `json:"processes_scanned"`
	ProcessesSkipped                   int            `json:"processes_skipped"`
	Matches                            int            `json:"matches"`
	EvidenceArtifacts                  int            `json:"evidence_artifacts"`
	HexdumpEvidenceArtifacts           int            `json:"hexdump_evidence_artifacts,omitempty"`
	HexdumpEvidenceDeduped             int            `json:"hexdump_evidence_deduped,omitempty"`
	HexdumpEvidenceSkippedByLimit      int            `json:"hexdump_evidence_skipped_by_limit,omitempty"`
	HexdumpEvidenceSkippedByBytesLimit int            `json:"hexdump_evidence_skipped_by_bytes_limit,omitempty"`
	HexdumpEvidenceErrors              int            `json:"hexdump_evidence_errors,omitempty"`
	HexdumpEvidenceBytes               uint64         `json:"hexdump_evidence_bytes,omitempty"`
	MiniDumpEligible                   int            `json:"minidump_eligible,omitempty"`
	MiniDumpAttempts                   int            `json:"minidump_attempts,omitempty"`
	MiniDumpWritten                    int            `json:"minidump_written,omitempty"`
	MiniDumpSkippedByLimit             int            `json:"minidump_skipped_by_limit,omitempty"`
	MiniDumpFailed                     int            `json:"minidump_failed,omitempty"`
	MiniDumpFailedByKind               map[string]int `json:"minidump_failed_by_kind,omitempty"`
	DegradedProcesses                  int            `json:"degraded_processes"`
	SkippedReasons                     map[string]int `json:"skipped_reasons,omitempty"`
}

type memscanProcess struct {
	Pid        int               `json:"pid"`
	Name       string            `json:"name,omitempty"`
	Exe        string            `json:"exe,omitempty"`
	Status     string            `json:"status"`
	SkipReason string            `json:"skip_reason,omitempty"`
	Error      string            `json:"error,omitempty"`
	Stats      *memscanStats     `json:"stats,omitempty"`
	Matches    []memscanMatch    `json:"matches,omitempty"`
	Evidence   []memscanEvidence `json:"evidence,omitempty"`
	MiniDump   *memscanMiniDump  `json:"minidump,omitempty"`
	Notes      []string          `json:"notes,omitempty"`
}

type memscanStats struct {
	RegionsEnumerated int                           `json:"regions_enumerated"`
	RegionsMatched    int                           `json:"regions_matched"`
	RegionsRead       int                           `json:"regions_read"`
	BytesRead         uint64                        `json:"bytes_read"`
	ReadAttempts      int                           `json:"read_attempts"`
	ReadErrors        int                           `json:"read_errors"`
	ReadErrorsByKind  map[memscan.ReadErrorKind]int `json:"read_errors_by_kind,omitempty"`
	Degraded          bool                          `json:"degraded"`
	DegradedReasons   []string                      `json:"degraded_reasons,omitempty"`
}

type memscanMatch struct {
	Pid            int                     `json:"pid"`
	ProcessName    string                  `json:"process_name,omitempty"`
	RuleName       string                  `json:"rule_name"`
	Tags           []string                `json:"tags,omitempty"`
	Description    string                  `json:"description,omitempty"`
	Region         memscanRegion           `json:"region"`
	Strings        []memscanMatchedString  `json:"strings,omitempty"`
	Risk           scoring.RiskScore       `json:"risk"`
	Remediation    scoring.RemediationPlan `json:"remediation"`
	Partial        bool                    `json:"partial"`
	PartialReasons []string                `json:"partial_reasons,omitempty"`
}

type memscanRegion struct {
	BaseAddress uint64 `json:"base_address"`
	Size        uint64 `json:"size"`
	Protection  uint32 `json:"protection"`
}

type memscanMatchedString struct {
	Identifier string   `json:"identifier"`
	Offsets    []uint64 `json:"offsets,omitempty"`
}

type memscanEvidence struct {
	Kind          string                        `json:"kind"`
	Path          string                        `json:"path"`
	Bytes         uint64                        `json:"bytes"`
	SHA256        string                        `json:"sha256,omitempty"`
	RuleName      string                        `json:"rule_name,omitempty"`
	Tags          []string                      `json:"tags,omitempty"`
	StartAddress  uint64                        `json:"start_address,omitempty"`
	Region        *memscanRegion                `json:"region,omitempty"`
	OffsetSummary *memscanEvidenceOffsetSummary `json:"offset_summary,omitempty"`
}

type memscanMiniDump struct {
	Status    string `json:"status"`
	Path      string `json:"path,omitempty"`
	Bytes     uint64 `json:"bytes,omitempty"`
	ErrorKind string `json:"error_kind,omitempty"`
	Error     string `json:"error,omitempty"`
}

type hexdumpEvidenceKey struct {
	Rule          string
	RegionBase    uintptr
	RegionSize    uintptr
	RegionProtect uint32
}

type hexdumpEvidenceAggregate struct {
	evidenceIndex int
	offsets       hexdumpOffsetsAgg
}

type memscanEvidenceOffsetSummary struct {
	MatchCount       int                    `json:"match_count,omitempty"`
	OffsetsObserved  int                    `json:"offsets_observed,omitempty"`
	OffsetsCaptured  int                    `json:"offsets_captured,omitempty"`
	OffsetsTruncated bool                   `json:"offsets_truncated,omitempty"`
	Strings          []memscanMatchedString `json:"strings,omitempty"`
}

type hexdumpOffsetsAgg struct {
	matchCount       int
	offsetsObserved  int
	offsetsCaptured  int
	offsetsTruncated bool
	byIdentifier     map[string]map[uint64]struct{}
}

func (a *hexdumpOffsetsAgg) add(chunk memscan.Chunk, match engine.Match, maxOffsets int) {
	a.matchCount++
	for _, s := range match.Strings {
		for _, offset := range s.Offsets {
			if offset < 0 {
				continue
			}
			a.offsetsObserved++
			if maxOffsets > 0 && a.offsetsCaptured >= maxOffsets {
				a.offsetsTruncated = true
				continue
			}
			addr := uint64(chunk.Address) + uint64(offset)
			if a.byIdentifier == nil {
				a.byIdentifier = make(map[string]map[uint64]struct{}, 4)
			}
			entry := a.byIdentifier[s.Identifier]
			if entry == nil {
				entry = make(map[uint64]struct{}, 4)
				a.byIdentifier[s.Identifier] = entry
			}
			if _, ok := entry[addr]; ok {
				continue
			}
			entry[addr] = struct{}{}
			a.offsetsCaptured++
		}
	}
}

func (a *hexdumpOffsetsAgg) summary() *memscanEvidenceOffsetSummary {
	if a.matchCount == 0 {
		return nil
	}
	out := &memscanEvidenceOffsetSummary{
		MatchCount:       a.matchCount,
		OffsetsObserved:  a.offsetsObserved,
		OffsetsCaptured:  a.offsetsCaptured,
		OffsetsTruncated: a.offsetsTruncated,
	}
	if len(a.byIdentifier) == 0 {
		return out
	}

	stringsOut := make([]memscanMatchedString, 0, len(a.byIdentifier))
	for identifier, offsets := range a.byIdentifier {
		entry := memscanMatchedString{Identifier: identifier}
		for addr := range offsets {
			entry.Offsets = append(entry.Offsets, addr)
		}
		sort.Slice(entry.Offsets, func(i, j int) bool { return entry.Offsets[i] < entry.Offsets[j] })
		if len(entry.Offsets) == 0 {
			entry.Offsets = nil
		}
		stringsOut = append(stringsOut, entry)
	}
	sort.Slice(stringsOut, func(i, j int) bool { return stringsOut[i].Identifier < stringsOut[j].Identifier })
	out.Strings = stringsOut
	if len(out.Strings) == 0 {
		out.Strings = nil
	}
	return out
}

func (opt *YaraMemScanOptions) Action(c *cli.Context) error {
	if runtime.GOOS != "windows" {
		return cli.Exit(memscan.ErrUnsupportedPlatform.Error(), 1)
	}
	if err := validateMemscanTargets(opt.Pid, opt.All); err != nil {
		return cli.Exit(err.Error(), 1)
	}
	if opt.MaxRegions < 0 {
		return cli.Exit("memscan: --max-regions must be >= 0", 1)
	}
	if opt.Timeout < 0 {
		return cli.Exit("memscan: --timeout must be >= 0", 1)
	}
	if opt.EvidenceContextBytes < 0 {
		return cli.Exit("memscan: --evidence-context-bytes must be >= 0", 1)
	}
	if opt.EvidenceMaxArtifacts < 0 {
		return cli.Exit("memscan: --evidence-max-artifacts must be >= 0", 1)
	}
	if opt.EvidenceMaxTotal < 0 {
		return cli.Exit("memscan: --evidence-max-total must be >= 0", 1)
	}
	if opt.EvidenceMaxOffsets < 0 {
		return cli.Exit("memscan: --evidence-max-offsets must be >= 0", 1)
	}
	if opt.MiniDumpMaxProcesses < 0 {
		return cli.Exit("memscan: --minidump-max-processes must be >= 0", 1)
	}

	start := time.Now()
	requestedBackend := resolveBackendMode(opt.Backend)
	result, err := backend.Load(backend.Options{
		RulePath: opt.RulePath,
		Mode:     requestedBackend,
	})
	if err != nil {
		return err
	}
	writeYaraBackendSummary(os.Stdout, requestedBackend, result)

	ctx := c.Context
	var cancel context.CancelFunc
	if opt.Timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, opt.Timeout)
		defer cancel()
	}

	manager := internal.GetReportManager()

	targets, err := opt.resolveTargets()
	if err != nil {
		return err
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
		if ctx.Err() != nil {
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
			stats, walkErr := scanProc.Walk(ctx, scanOpts, func(chunk memscan.Chunk) error {
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
						processEntry.Notes = append(processEntry.Notes, fmt.Sprintf("证据保全失败(rule=%s): %v", match.RuleName, err))
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
						processEntry.Notes = append(processEntry.Notes, fmt.Sprintf("证据保全失败(rule=%s): %v", match.RuleName, err))
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
					processEntry.Notes = append(processEntry.Notes, fmt.Sprintf("MiniDump 生成失败(%s): %v", kind, err))
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
	f, path, err := manager.CreateFile("detect/memscan", fileName, "json")
	if err != nil {
		return err
	}
	if err := writeMemscanReport(f, report); err != nil {
		_ = f.Close()
		return err
	}
	_ = f.Close()

	notes := make([]string, 0)
	if ctx.Err() != nil && errors.Is(ctx.Err(), context.DeadlineExceeded) {
		notes = append(notes, color.Yellow.Sprintf("全局超时触发: %s", opt.Timeout))
	}
	if report.Summary.ProcessesSkipped > 0 {
		notes = append(notes, color.Yellow.Sprintf("跳过进程: %d", report.Summary.ProcessesSkipped))
	}
	if report.Summary.DegradedProcesses > 0 {
		notes = append(notes, color.Yellow.Sprintf("退化扫描进程: %d", report.Summary.DegradedProcesses))
	}
	if report.Summary.EvidenceArtifacts > 0 {
		notes = append(notes, color.Yellow.Sprintf("证据保全产物: %d（包含敏感数据，默认关闭）", report.Summary.EvidenceArtifacts))
	}
	if report.Summary.HexdumpEvidenceDeduped > 0 {
		notes = append(notes, color.Yellow.Sprintf("证据去重跳过: %d（按 rule+region）", report.Summary.HexdumpEvidenceDeduped))
	}
	if report.Summary.HexdumpEvidenceSkippedByLimit > 0 {
		notes = append(notes, color.Yellow.Sprintf("证据限额跳过: %d", report.Summary.HexdumpEvidenceSkippedByLimit))
	}
	if report.Summary.HexdumpEvidenceSkippedByBytesLimit > 0 {
		notes = append(notes, color.Yellow.Sprintf("证据字节预算跳过: %d", report.Summary.HexdumpEvidenceSkippedByBytesLimit))
	}
	if report.Summary.HexdumpEvidenceBytes > 0 {
		notes = append(notes, color.Yellow.Sprintf("证据保全原始字节: %d", report.Summary.HexdumpEvidenceBytes))
	}
	if report.Summary.MiniDumpFailed > 0 {
		notes = append(notes, color.Yellow.Sprintf("MiniDump 失败: %d", report.Summary.MiniDumpFailed))
	}
	if report.Summary.MiniDumpSkippedByLimit > 0 {
		notes = append(notes, color.Yellow.Sprintf("MiniDump 限额跳过: %d", report.Summary.MiniDumpSkippedByLimit))
	}

	outputs := []reporting.OutputRecord{
		{Label: "内存扫描报告", Path: path},
	}
	if report.Summary.EvidenceArtifacts > 0 {
		evidenceDir := filepath.Join(manager.BaseDir(), "detect", "memscan", "evidence")
		outputs = append(outputs, reporting.OutputRecord{Label: "证据保全目录", Path: evidenceDir})
	}

	manager.PrintSummary(reporting.Summary{
		Command:  "detect memscan",
		Duration: time.Since(start),
		Outputs:  outputs,
		Risks:    riskCounts,
		Notes:    notes,
		Status:   "完成",
	})
	return nil
}

func validateMemscanTargets(pid int, all bool) error {
	if all && pid > 0 {
		return errors.New("memscan: specify exactly one of --pid or --all")
	}
	if all {
		return nil
	}
	if pid <= 0 {
		return errors.New("memscan: either --pid <pid> or --all is required")
	}
	return nil
}

func (opt *YaraMemScanOptions) resolveTargets() ([]*process.Process, error) {
	if opt.All {
		procs, err := listProcessesFn()
		if err != nil {
			return nil, fmt.Errorf("enumerate processes: %w", err)
		}
		self := os.Getpid()
		filtered := make([]*process.Process, 0, len(procs))
		for _, p := range procs {
			if p == nil || p.Pid <= 0 || int(p.Pid) == self {
				continue
			}
			filtered = append(filtered, p)
		}
		sort.Slice(filtered, func(i, j int) bool { return filtered[i].Pid < filtered[j].Pid })
		return filtered, nil
	}

	proc, err := process.NewProcess(int32(opt.Pid))
	if err != nil {
		return nil, fmt.Errorf("lookup process pid=%d: %w", opt.Pid, err)
	}
	return []*process.Process{proc}, nil
}

type memscanChunkScanError struct {
	cause error
}

func (e memscanChunkScanError) Error() string {
	return fmt.Sprintf("yara scan chunk: %v", e.cause)
}

func (e memscanChunkScanError) Unwrap() error {
	return e.cause
}

func writeMemscanReport(f *os.File, report memscanReport) error {
	if f == nil {
		return errors.New("memscan: report file is nil")
	}
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}

func memscanStatsFrom(stats memscan.Stats) memscanStats {
	out := memscanStats{
		RegionsEnumerated: stats.RegionsEnumerated,
		RegionsMatched:    stats.RegionsMatched,
		RegionsRead:       stats.RegionsRead,
		BytesRead:         stats.BytesRead,
		ReadAttempts:      stats.ReadAttempts,
		ReadErrors:        stats.ReadErrors,
		ReadErrorsByKind:  stats.ReadErrorsByKind,
		Degraded:          stats.Degraded,
		DegradedReasons:   append([]string{}, stats.DegradedReasons...),
	}
	if out.ReadErrorsByKind == nil || len(out.ReadErrorsByKind) == 0 {
		out.ReadErrorsByKind = nil
	}
	if len(out.DegradedReasons) == 0 {
		out.DegradedReasons = nil
	}
	return out
}

func convertMemscanMatch(pid int, processName string, chunk memscan.Chunk, match engine.Match) memscanMatch {
	out := memscanMatch{
		Pid:         pid,
		ProcessName: processName,
		RuleName:    match.RuleName,
		Tags:        append([]string{}, match.Tags...),
		Description: match.Description,
		Region: memscanRegion{
			BaseAddress: uint64(chunk.Region.Base),
			Size:        uint64(chunk.Region.Size),
			Protection:  chunk.Region.Protect,
		},
		Partial:        match.Partial,
		PartialReasons: append([]string{}, match.PartialReasons...),
	}

	stringsOut := make([]memscanMatchedString, 0, len(match.Strings))
	for _, s := range match.Strings {
		entry := memscanMatchedString{
			Identifier: s.Identifier,
		}
		for _, offset := range s.Offsets {
			if offset < 0 {
				continue
			}
			entry.Offsets = append(entry.Offsets, uint64(chunk.Address)+uint64(offset))
		}
		if len(entry.Offsets) == 0 {
			entry.Offsets = nil
		}
		stringsOut = append(stringsOut, entry)
	}
	out.Strings = stringsOut
	if len(out.Strings) == 0 {
		out.Strings = nil
	}

	out.Risk = scoring.Calculate(match.RuleName, match.ScoreHints, match.Tags)
	if match.Partial {
		out.Risk.Total *= 0.8
		out.Risk.Level = out.Risk.Level + " (partial)"
	}
	out.Remediation = scoring.ResolveRemediation(match.RuleName, match.Tags)

	if len(out.PartialReasons) == 0 {
		out.PartialReasons = nil
	}
	if len(out.Tags) == 0 {
		out.Tags = nil
	}
	return out
}

func normalizeRiskLevel(level string) string {
	trimmed := strings.TrimSpace(level)
	if trimmed == "" {
		return ""
	}
	if idx := strings.Index(trimmed, " "); idx > 0 {
		trimmed = trimmed[:idx]
	}
	return trimmed
}

func classifyProcessSkipReason(err error) string {
	if err == nil {
		return string(memscan.ReadErrorOther)
	}
	if errors.Is(err, memscan.ErrUnsupportedPlatform) {
		return "unsupported"
	}

	kind := memscan.ClassifyReadError(err)
	if kind == "" {
		return string(memscan.ReadErrorOther)
	}
	return string(kind)
}

func plannedMemscanHexdumpBytes(chunk memscan.Chunk, match engine.Match, opt *YaraMemScanOptions) (uint64, error) {
	start, end, _, err := planMemscanHexdumpSnippet(chunk, match, opt)
	if err != nil {
		return 0, err
	}
	if start >= end {
		return 0, errors.New("memscan evidence: invalid slice bounds")
	}
	return uint64(end - start), nil
}

func planMemscanHexdumpSnippet(chunk memscan.Chunk, match engine.Match, opt *YaraMemScanOptions) (start, end int, startAddress uint64, err error) {
	if opt == nil {
		return 0, 0, 0, errors.New("memscan evidence: options is nil")
	}
	if len(chunk.Data) == 0 {
		return 0, 0, 0, errors.New("memscan evidence: empty chunk")
	}

	firstOffset, ok := firstMatchOffset(match)
	if !ok {
		firstOffset = 0
	}
	if firstOffset < 0 {
		firstOffset = 0
	}
	if firstOffset > len(chunk.Data) {
		firstOffset = 0
	}

	start = firstOffset - opt.EvidenceContextBytes
	if start < 0 {
		start = 0
	}
	end = len(chunk.Data)
	if opt.EvidenceMaxBytes > 0 {
		if start+int(opt.EvidenceMaxBytes) < end {
			end = start + int(opt.EvidenceMaxBytes)
		}
	}
	if start >= end {
		return 0, 0, 0, errors.New("memscan evidence: invalid slice bounds")
	}
	return start, end, uint64(chunk.Address) + uint64(start), nil
}

func writeMemscanHexdumpEvidence(manager *reporting.Manager, pid int, processName string, chunk memscan.Chunk, match engine.Match, opt *YaraMemScanOptions) (memscanEvidence, error) {
	if manager == nil {
		return memscanEvidence{}, errors.New("memscan evidence: report manager is nil")
	}

	start, end, startAddr, err := planMemscanHexdumpSnippet(chunk, match, opt)
	if err != nil {
		return memscanEvidence{}, err
	}

	snippet := make([]byte, end-start)
	copy(snippet, chunk.Data[start:end])
	digest := sha256.Sum256(snippet)

	var buf bytes.Buffer
	fmt.Fprintf(&buf, "kind: hexdump\npid: %d\nprocess: %s\nrule: %s\n", pid, processName, match.RuleName)
	if len(match.Tags) > 0 {
		fmt.Fprintf(&buf, "tags: %s\n", strings.Join(match.Tags, ","))
	}
	fmt.Fprintf(&buf, "region_base: 0x%x\nregion_size: %d\nprotection: 0x%x\n", chunk.Region.Base, chunk.Region.Size, chunk.Region.Protect)
	fmt.Fprintf(&buf, "dump_start_address: 0x%x\ndump_bytes: %d\nsha256: %s\n\n", startAddr, len(snippet), hex.EncodeToString(digest[:]))
	buf.WriteString(hex.Dump(snippet))

	name := fmt.Sprintf("pid-%d-%s-0x%x", pid, match.RuleName, startAddr)
	f, path, err := manager.CreateFile("detect/memscan/evidence", name, "txt")
	if err != nil {
		return memscanEvidence{}, err
	}
	_ = os.Chmod(path, 0o600)
	if _, err := f.Write(buf.Bytes()); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return memscanEvidence{}, err
	}
	if err := f.Close(); err != nil {
		return memscanEvidence{}, err
	}

	ev := memscanEvidence{
		Kind:         "hexdump",
		Path:         path,
		Bytes:        uint64(len(snippet)),
		SHA256:       hex.EncodeToString(digest[:]),
		RuleName:     match.RuleName,
		Tags:         append([]string{}, match.Tags...),
		StartAddress: startAddr,
		Region: &memscanRegion{
			BaseAddress: uint64(chunk.Region.Base),
			Size:        uint64(chunk.Region.Size),
			Protection:  chunk.Region.Protect,
		},
	}
	if len(ev.Tags) == 0 {
		ev.Tags = nil
	}
	return ev, nil
}

func firstMatchOffset(match engine.Match) (int, bool) {
	found := false
	minOffset := 0
	for _, s := range match.Strings {
		for _, offset := range s.Offsets {
			if offset < 0 {
				continue
			}
			if !found || offset < minOffset {
				minOffset = offset
				found = true
			}
		}
	}
	return minOffset, found
}

func writeMemscanMiniDumpEvidence(manager *reporting.Manager, pid int) (memscanEvidence, error) {
	if manager == nil {
		return memscanEvidence{}, errors.New("memscan evidence: report manager is nil")
	}
	if pid <= 0 {
		return memscanEvidence{}, fmt.Errorf("memscan evidence: invalid pid %d", pid)
	}

	f, path, err := manager.CreateFile("detect/memscan/evidence", fmt.Sprintf("pid-%d-minidump", pid), "dmp")
	if err != nil {
		return memscanEvidence{}, err
	}
	_ = os.Chmod(path, 0o600)

	if err := writeMiniDump(pid, f); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return memscanEvidence{}, err
	}
	if err := f.Close(); err != nil {
		return memscanEvidence{}, err
	}

	stat, err := os.Stat(path)
	if err != nil {
		return memscanEvidence{}, err
	}

	return memscanEvidence{
		Kind:  "minidump",
		Path:  path,
		Bytes: uint64(stat.Size()),
	}, nil
}
