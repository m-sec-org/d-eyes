//go:build !windows

package detect

import (
	"errors"

	"github.com/m-sec-org/d-eyes/agent/internal/detect/memscan"
)

func classifyMiniDumpError(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, memscan.ErrUnsupportedPlatform) {
		return "unsupported"
	}
	kind := memscan.ClassifyReadError(err)
	if kind == "" {
		return "other"
	}
	return string(kind)
}
