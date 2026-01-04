//go:build linux || windows || darwin

package detect

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/urfave/cli/v2"

	"github.com/m-sec-org/d-eyes/agent/internal"
	"github.com/m-sec-org/d-eyes/agent/internal/detect/backend"
	"github.com/m-sec-org/d-eyes/agent/internal/detect/engine"
	"github.com/m-sec-org/d-eyes/agent/internal/detect/engine/goengine"
	"github.com/m-sec-org/d-eyes/agent/pkg/color"
)

var YaraDiagOption *YaraDiagOptions

func init() {
	YaraDiagOption = NewDetectPluginYaraDiag()
	internal.RegisterDetectSubcommands(YaraDiagOption)
}

type YaraDiagOptions struct {
	RulePath string
	Backend  string
	JSON     bool
	internal.BaseOption
}

func NewDetectPluginYaraDiag() *YaraDiagOptions {
	return &YaraDiagOptions{
		BaseOption: internal.BaseOption{
			Name:        "yara diag",
			Author:      "msec",
			Description: "Output YARA backend/rules diagnostic information for CI and troubleshooting",
		},
	}
}

func (opt *YaraDiagOptions) InitCommand() []*cli.Command {
	return []*cli.Command{
		{
			Name:   "diag",
			Usage:  "Diagnose YARA backend, rules coverage, and missing families",
			Action: opt.Action,
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:        "rule",
					Aliases:     []string{"r"},
					Usage:       "Custom rule file or directory (defaults to embedded set)",
					Destination: &YaraDiagOption.RulePath,
				},
				&cli.StringFlag{
					Name:        "backend",
					Usage:       "YARA backend (auto|native|portable). Defaults to env D_EYES_YARA_BACKEND or auto.",
					Destination: &YaraDiagOption.Backend,
				},
				&cli.BoolFlag{
					Name:        "json",
					Usage:       "Output diagnostics as JSON (for CI)",
					Destination: &YaraDiagOption.JSON,
					Value:       false,
				},
			},
		},
	}
}

type yaraFamilyDiag struct {
	TotalFiles   int            `json:"total_files"`
	LoadedFiles  int            `json:"loaded_files"`
	SkippedFiles int            `json:"skipped_files"`
	SkipReasons  map[string]int `json:"skip_reasons,omitempty"`
}

type yaraDiagAnalysis struct {
	TotalFiles   int                        `json:"total_files"`
	LoadedFiles  int                        `json:"loaded_files"`
	SkippedFiles int                        `json:"skipped_files"`
	SkipReasons  map[string]int             `json:"skip_reasons,omitempty"`
	Families     map[string]*yaraFamilyDiag `json:"families"`
}

type yaraDiagOutput struct {
	RequestedBackend backend.Mode        `json:"requested_backend"`
	EffectiveBackend backend.Mode        `json:"effective_backend"`
	Engine           string              `json:"engine"`
	RuleCount        int                 `json:"rule_count"`
	Version          string              `json:"version"`
	Source           string              `json:"source"`
	CustomHash       string              `json:"custom_hash,omitempty"`
	LoadedAt         time.Time           `json:"loaded_at"`
	Coverage         float64             `json:"coverage"`
	Stats            goengine.BuildStats `json:"build_stats"`
	Fallback         bool                `json:"fallback"`
	FallbackReason   string              `json:"fallback_reason,omitempty"`
	NativeAvailable  bool                `json:"native_available"`
	Analysis         yaraDiagAnalysis    `json:"analysis"`
	MissingFamilies  []string            `json:"missing_families,omitempty"`
}

func (opt *YaraDiagOptions) Action(_ *cli.Context) error {
	requested := resolveBackendMode(opt.Backend)
	result, err := backend.Load(backend.Options{
		RulePath: opt.RulePath,
		Mode:     requested,
	})
	if err != nil {
		return err
	}
	snapshot := result.Manager.Snapshot()
	files := result.Manager.Sources()

	var analysis yaraDiagAnalysis
	if result.Backend == backend.ModeNative {
		analysis, err = analyzeSourcesNative(files)
		if err != nil {
			return err
		}
	} else {
		analysis = analyzeSourcesPortable(files)
	}

	missingFamilies := computeMissingFamilies(analysis.Families)

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
		MissingFamilies:  missingFamilies,
	}

	if opt.JSON {
		blob, err := json.MarshalIndent(out, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(blob))
		return nil
	}

	fmt.Printf("YARA diag: requested=%s effective=%s engine=%s version=%s rules=%d\n",
		out.RequestedBackend, out.EffectiveBackend, out.Engine, out.Version, out.RuleCount)
	if out.Source != "" {
		fmt.Printf("Rules source=%s loaded_at=%s\n", out.Source, out.LoadedAt.UTC().Format(time.RFC3339))
	}
	if out.CustomHash != "" {
		fmt.Printf("Custom rules hash=%s\n", out.CustomHash)
	}
	if out.Fallback && strings.TrimSpace(out.FallbackReason) != "" {
		fmt.Println(color.Yellow.Sprintf("Fallback reason: %s", out.FallbackReason))
	}

	if out.Stats.TotalRuleFiles > 0 {
		fmt.Printf("Coverage: %.1f%% (%d/%d files) loaded_rules=%d skipped_files=%d\n",
			out.Coverage*100,
			out.Stats.LoadedRuleFiles,
			out.Stats.TotalRuleFiles,
			out.Stats.LoadedRules,
			out.Stats.SkippedRuleFiles,
		)
	}
	if len(out.Stats.SkipReasons) > 0 {
		fmt.Printf("Skip reasons: %s\n", strings.Join(formatReasonCounts(out.Stats.SkipReasons), ", "))
	}

	if len(missingFamilies) == 0 {
		fmt.Println(color.Green.Sprint("Families: OK (no missing family in current ruleset)"))
		return nil
	}

	fmt.Println(color.Yellow.Sprint("Missing families (loaded_files=0):"))
	for _, family := range missingFamilies {
		info := analysis.Families[family]
		if info == nil {
			continue
		}
		reasons := ""
		if len(info.SkipReasons) > 0 {
			reasons = " reasons=" + strings.Join(formatReasonCounts(info.SkipReasons), ", ")
		}
		fmt.Printf("- %s: %d/%d loaded%s\n", family, info.LoadedFiles, info.TotalFiles, reasons)
	}

	if out.EffectiveBackend == backend.ModePortable && out.Stats.TotalRuleFiles > 0 && out.Stats.LoadedRuleFiles == 0 && out.NativeAvailable {
		fmt.Println(color.Yellow.Sprint("Hint: portable backend loaded 0 rule files; try building/running with -tags yara_native to improve coverage."))
	} else if out.EffectiveBackend == backend.ModePortable && !out.NativeAvailable {
		fmt.Println(color.Yellow.Sprint("Hint: build with -tags yara_native (CGO + libyara) to enable native backend diagnostics and higher coverage."))
	}
	return nil
}

func analyzeSourcesPortable(files map[string][]byte) yaraDiagAnalysis {
	analysis := yaraDiagAnalysis{
		Families: make(map[string]*yaraFamilyDiag),
	}
	if len(files) == 0 {
		return analysis
	}

	keys := make([]string, 0, len(files))
	for k := range files {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, path := range keys {
		if !strings.HasSuffix(strings.ToLower(path), ".yar") {
			continue
		}
		family := ruleFamilyFromPath(path)
		entry := analysis.Families[family]
		if entry == nil {
			entry = &yaraFamilyDiag{}
			analysis.Families[family] = entry
		}
		entry.TotalFiles++
		analysis.TotalFiles++

		_, err := goengine.RuleFromSource(path, files[path])
		if err != nil {
			reason := classifyPortableSkipReason(err)
			entry.SkippedFiles++
			analysis.SkippedFiles++
			incrementReason(entry, reason)
			if analysis.SkipReasons == nil {
				analysis.SkipReasons = make(map[string]int)
			}
			analysis.SkipReasons[reason]++
			continue
		}
		entry.LoadedFiles++
		analysis.LoadedFiles++
	}

	return analysis
}

func classifyPortableSkipReason(err error) string {
	if isPortableUnsupportedError(err) {
		return "unsupported-feature"
	}
	if err == nil {
		return "unknown"
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "syntax"):
		return "syntax-error"
	case strings.Contains(msg, "duplicate"):
		return "duplicate-definition"
	default:
		return "parse-error"
	}
}

func isPortableUnsupportedError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, engine.ErrUnsupportedFeature) {
		return true
	}
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "unsupported") {
		return true
	}
	if strings.Contains(msg, "invalid hex token") {
		return true
	}
	if strings.Contains(msg, "invalid group element") {
		return true
	}
	return false
}

func ruleFamilyFromPath(path string) string {
	base := filepath.Base(path)
	parts := strings.SplitN(base, ".", 2)
	if len(parts) == 0 || strings.TrimSpace(parts[0]) == "" {
		return "unknown"
	}
	return parts[0]
}

func incrementReason(entry *yaraFamilyDiag, reason string) {
	if entry.SkipReasons == nil {
		entry.SkipReasons = make(map[string]int)
	}
	reason = strings.TrimSpace(reason)
	if reason == "" {
		reason = "unknown"
	}
	entry.SkipReasons[reason]++
}

func formatReasonCounts(reasons map[string]int) []string {
	if len(reasons) == 0 {
		return nil
	}
	type item struct {
		k string
		v int
	}
	items := make([]item, 0, len(reasons))
	for k, v := range reasons {
		items = append(items, item{k: k, v: v})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].v != items[j].v {
			return items[i].v > items[j].v
		}
		return items[i].k < items[j].k
	})
	out := make([]string, 0, len(items))
	for _, it := range items {
		out = append(out, fmt.Sprintf("%s=%d", it.k, it.v))
	}
	return out
}

func computeMissingFamilies(families map[string]*yaraFamilyDiag) []string {
	if len(families) == 0 {
		return nil
	}
	type item struct {
		name  string
		total int
	}
	missing := make([]item, 0)
	for name, info := range families {
		if info == nil {
			continue
		}
		if info.LoadedFiles == 0 && info.TotalFiles > 0 {
			missing = append(missing, item{name: name, total: info.TotalFiles})
		}
	}
	sort.Slice(missing, func(i, j int) bool {
		if missing[i].total != missing[j].total {
			return missing[i].total > missing[j].total
		}
		return missing[i].name < missing[j].name
	})
	out := make([]string, 0, len(missing))
	for _, it := range missing {
		out = append(out, it.name)
	}
	return out
}
