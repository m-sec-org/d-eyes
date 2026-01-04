//go:build !yara_native

package backend

import "github.com/m-sec-org/d-eyes/agent/internal/detect/rules"

func nativeFactory() rules.RuleEngineFactory {
	return nil
}

