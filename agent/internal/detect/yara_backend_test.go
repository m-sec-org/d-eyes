package detect

import (
	"os"
	"testing"

	"github.com/m-sec-org/d-eyes/agent/internal/detect/backend"
)

func TestResolveBackendModeOrder(t *testing.T) {
	os.Unsetenv("D_EYES_YARA_BACKEND")
	if mode := resolveBackendMode("native"); mode != backend.ModeNative {
		t.Fatalf("expected native, got %s", mode)
	}
	if mode := resolveBackendMode("unknown"); mode != backend.ModePortable {
		t.Fatalf("unknown should fallback to portable")
	}
}

func TestResolveBackendModeFromEnv(t *testing.T) {
	t.Setenv("D_EYES_YARA_BACKEND", "portable")
	if mode := resolveBackendMode(""); mode != backend.ModePortable {
		t.Fatalf("env should control mode")
	}
}
