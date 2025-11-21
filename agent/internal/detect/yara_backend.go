package detect

import (
	"os"
	"strings"

	"github.com/m-sec-org/d-eyes/agent/internal/detect/backend"
)

func resolveBackendMode(explicit string) backend.Mode {
	value := strings.ToLower(strings.TrimSpace(explicit))
	if value == "" {
		value = strings.ToLower(strings.TrimSpace(os.Getenv("D_EYES_YARA_BACKEND")))
	}
	switch value {
	case string(backend.ModeNative):
		return backend.ModeNative
	case string(backend.ModePortable):
		return backend.ModePortable
	case string(backend.ModeAuto), "":
		return backend.ModeAuto
	default:
		return backend.ModePortable
	}
}
