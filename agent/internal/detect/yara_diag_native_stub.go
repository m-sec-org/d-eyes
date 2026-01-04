//go:build !yara_native

package detect

import "fmt"

func analyzeSourcesNative(_ map[string][]byte) (yaraDiagAnalysis, error) {
	return yaraDiagAnalysis{}, fmt.Errorf("native diagnostics unavailable (build without -tags yara_native)")
}

func nativeDiagAvailable() bool {
	return false
}
