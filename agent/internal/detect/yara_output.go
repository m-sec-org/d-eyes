//go:build linux || windows || darwin

package detect

import (
	"fmt"
	"io"
	"strings"

	"github.com/m-sec-org/d-eyes/agent/internal/detect/backend"
	"github.com/m-sec-org/d-eyes/agent/pkg/color"
)

func writeYaraBackendSummary(w io.Writer, requested backend.Mode, result *backend.Result) {
	if w == nil || result == nil || result.Bundle == nil {
		return
	}

	bundle := result.Bundle
	fmt.Fprintf(w, "Loaded %d rules (requested=%s backend=%s engine=%s version=%s)\n",
		bundle.RuleCount(),
		requested,
		result.Backend,
		bundle.Name(),
		bundle.Version(),
	)

	if result.Stats.TotalRuleFiles > 0 {
		fmt.Fprintf(w, "Rule coverage: %.1f%% (%d/%d files, skipped=%d)\n",
			result.Stats.Coverage()*100,
			result.Stats.LoadedRuleFiles,
			result.Stats.TotalRuleFiles,
			result.Stats.SkippedRuleFiles,
		)
		if result.Stats.SkippedRuleFiles > 0 && len(result.Stats.SkipReasons) > 0 {
			fmt.Fprintf(w, "Skip reasons: %s\n", strings.Join(formatReasonCounts(result.Stats.SkipReasons), ", "))
		}
	}

	if result.Fallback && strings.TrimSpace(result.FallbackReason) != "" {
		fmt.Fprintln(w, color.Yellow.Sprintf("Fallback reason: %s", result.FallbackReason))
	}
}
