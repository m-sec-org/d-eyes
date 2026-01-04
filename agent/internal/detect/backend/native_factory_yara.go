//go:build yara_native

package backend

import (
	"github.com/m-sec-org/d-eyes/agent/internal/detect/engine"
	"github.com/m-sec-org/d-eyes/agent/internal/detect/engine/goengine"
	"github.com/m-sec-org/d-eyes/agent/internal/detect/engine/nativeengine"
	"github.com/m-sec-org/d-eyes/agent/internal/detect/rules"
)

type nativeRuleEngineFactory struct{}

func (nativeRuleEngineFactory) FromSources(files map[string][]byte, version string) (engine.RuleBundle, goengine.BuildStats, error) {
	return nativeengine.CompileFromSources(files, version)
}

func nativeFactory() rules.RuleEngineFactory {
	return nativeRuleEngineFactory{}
}

