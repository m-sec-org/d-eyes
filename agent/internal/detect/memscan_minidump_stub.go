//go:build !windows

package detect

import (
	"os"

	"github.com/m-sec-org/d-eyes/agent/internal/detect/memscan"
)

func writeMiniDump(_ int, _ *os.File) error {
	return memscan.ErrUnsupportedPlatform
}
