//go:build windows

package detect

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"

	"github.com/m-sec-org/d-eyes/agent/internal/detect/memscan"
)

func classifyMiniDumpError(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, memscan.ErrUnsupportedPlatform) {
		return "unsupported"
	}

	var pathErr *os.PathError
	if errors.As(err, &pathErr) {
		return "io-error"
	}

	var dllErr *windows.DLLError
	if errors.As(err, &dllErr) {
		if strings.EqualFold(filepath.Base(dllErr.ObjName), "dbghelp.dll") {
			return "dbghelp-missing"
		}
		return "dll-load-failed"
	}

	kind := memscan.ClassifyReadError(err)
	if kind == "" {
		return "other"
	}
	return string(kind)
}
