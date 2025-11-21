package goengine

import "github.com/m-sec-org/d-eyes/agent/internal/detect/scoring"

// BuildStats 跟踪规则加载过程。
type BuildStats struct {
	TotalRuleFiles   int
	LoadedRuleFiles  int
	SkippedRuleFiles int
	LoadedRules      int
	SkipReasons      map[string]int
	ScoreHintsSeen   int
}

func (s *BuildStats) recordSuccess(ruleCount int) {
	s.LoadedRuleFiles++
	s.LoadedRules += ruleCount
}

func (s *BuildStats) recordRule(r *Rule) {
	if r == nil {
		return
	}
	if r.ScoreHints != (scoring.ScoreHints{}) {
		s.ScoreHintsSeen++
	}
}

func (s *BuildStats) recordSkip(reason string) {
	s.SkippedRuleFiles++
	if s.SkipReasons == nil {
		s.SkipReasons = make(map[string]int)
	}
	if reason == "" {
		reason = "unknown"
	}
	s.SkipReasons[reason]++
}

// Coverage 返回加载成功的文件占比。
func (s BuildStats) Coverage() float64 {
	if s.TotalRuleFiles == 0 {
		return 1.0
	}
	return float64(s.LoadedRuleFiles) / float64(s.TotalRuleFiles)
}

// Clone 返回深拷贝。
func (s BuildStats) Clone() BuildStats {
	clone := BuildStats{
		TotalRuleFiles:   s.TotalRuleFiles,
		LoadedRuleFiles:  s.LoadedRuleFiles,
		SkippedRuleFiles: s.SkippedRuleFiles,
		LoadedRules:      s.LoadedRules,
		ScoreHintsSeen:   s.ScoreHintsSeen,
	}
	if len(s.SkipReasons) > 0 {
		clone.SkipReasons = make(map[string]int, len(s.SkipReasons))
		for k, v := range s.SkipReasons {
			clone.SkipReasons[k] = v
		}
	}
	return clone
}
