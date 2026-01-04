//go:build yara_native

package detect

import (
	"fmt"
	"sort"
	"strings"

	yara "github.com/hillu/go-yara/v4"
)

func nativeDiagAvailable() bool {
	return true
}

func analyzeSourcesNative(files map[string][]byte) (yaraDiagAnalysis, error) {
	analysis := yaraDiagAnalysis{
		Families: make(map[string]*yaraFamilyDiag),
	}
	if len(files) == 0 {
		return analysis, nil
	}

	newCompiler := func() (*yara.Compiler, error) {
		compiler, err := yara.NewCompiler()
		if err != nil {
			return nil, err
		}
		compiler.DisableIncludes()
		return compiler, nil
	}

	compiler, err := newCompiler()
	if err != nil {
		return analysis, fmt.Errorf("yara native: init compiler: %w", err)
	}
	destroyCompiler := func() {
		if compiler == nil {
			return
		}
		compiler.Destroy()
		compiler = nil
	}
	defer destroyCompiler()

	keys := make([]string, 0, len(files))
	for k := range files {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	accepted := make([]string, 0, len(keys))
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

		raw := files[path]
		if len(raw) == 0 {
			reason := "empty-file"
			entry.SkippedFiles++
			analysis.SkippedFiles++
			incrementReason(entry, reason)
			if analysis.SkipReasons == nil {
				analysis.SkipReasons = make(map[string]int)
			}
			analysis.SkipReasons[reason]++
			continue
		}

		if err := compiler.AddString(string(raw), ""); err != nil {
			reason := classifyNativeCompileError(err)
			entry.SkippedFiles++
			analysis.SkippedFiles++
			incrementReason(entry, reason)
			if analysis.SkipReasons == nil {
				analysis.SkipReasons = make(map[string]int)
			}
			analysis.SkipReasons[reason]++

			destroyCompiler()
			compiler, err = newCompiler()
			if err != nil {
				return analysis, fmt.Errorf("yara native: init compiler: %w", err)
			}
			for _, prev := range accepted {
				if addErr := compiler.AddString(string(files[prev]), ""); addErr != nil {
					destroyCompiler()
					return analysis, fmt.Errorf("yara native: rebuild compiler after error: %w", addErr)
				}
			}
			continue
		}

		accepted = append(accepted, path)
		entry.LoadedFiles++
		analysis.LoadedFiles++
	}

	if len(accepted) == 0 {
		return analysis, nil
	}

	rules, err := compiler.GetRules()
	if err != nil {
		return analysis, fmt.Errorf("yara native: compile rules: %w", err)
	}
	rules.Destroy()
	return analysis, nil
}

func classifyNativeCompileError(err error) string {
	if err == nil {
		return "unknown"
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "syntax"):
		return "syntax-error"
	case strings.Contains(msg, "duplicate") || strings.Contains(msg, "already defined"):
		return "duplicate-definition"
	case strings.Contains(msg, "include"):
		return "include-error"
	default:
		return "compile-error"
	}
}
