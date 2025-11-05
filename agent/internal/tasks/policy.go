package tasks

import (
	"fmt"
	"strings"

	"github.com/m-sec-org/d-eyes/agent/pkg/config"
)

var severityWeight = map[string]int{
	"low":      1,
	"medium":   2,
	"high":     3,
	"critical": 4,
}

func evaluatePolicy(policy config.PolicyConfig, risks map[string]int) error {
	threshold := strings.ToLower(strings.TrimSpace(policy.FailOn))
	if threshold == "" || threshold == "none" {
		return nil
	}
	thresholdWeight := severityWeight[threshold]
	if thresholdWeight == 0 {
		thresholdWeight = severityWeight["high"]
	}
	for level, count := range risks {
		if count == 0 {
			continue
		}
		if severityWeight[strings.ToLower(level)] >= thresholdWeight {
			return fmt.Errorf("检测到 %d 个 %s 风险，已达到 fail_on 阈值 %s", count, level, threshold)
		}
	}
	return nil
}
