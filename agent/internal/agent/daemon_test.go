package agent

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/m-sec-org/d-eyes/agent/internal/tasks"
	"github.com/m-sec-org/d-eyes/agent/pkg/config"
)

func cloneFlags(src map[string]any) map[string]any {
	if src == nil {
		return make(map[string]any)
	}
	dst := make(map[string]any, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

func TestCLIAndRemoteContractAlignment(t *testing.T) {
	tmpDir := t.TempDir()
	baselineCfg := filepath.Join(tmpDir, "baseline.yaml")
	if err := os.WriteFile(baselineCfg, []byte("id: baseline"), 0o600); err != nil {
		t.Fatalf("write baseline cfg: %v", err)
	}
	supplychainRoot := filepath.Join(tmpDir, "project")
	if err := os.MkdirAll(supplychainRoot, 0o755); err != nil {
		t.Fatalf("mkdir supplychain root: %v", err)
	}

	cfg := config.Default()
	cfg.Tasks.Respond.Profile = "quick"
	cfg.Tasks.Respond.Targets = []string{"/var/log"}
	cfg.Tasks.Inventory.Profile = "deep"
	cfg.Tasks.Inventory.Targets = []string{"10.0.0.1/32"}
	cfg.Tasks.Inventory.Ports = "80,443"
	cfg.Tasks.Baseline.Config = baselineCfg
	cfg.Tasks.SupplyChain.Type = "json"

	testCases := []struct {
		name        string
		cliFlags    map[string]any
		remoteFlags map[string]any
		expectKeys  []string
	}{
		{
			name:       "respond",
			cliFlags:   map[string]any{},
			expectKeys: []string{"targets"},
		},
		{
			name: "inventory",
			cliFlags: map[string]any{
				"targets": "192.168.1.1,192.168.1.2",
				"ports":   "22,443",
			},
			remoteFlags: map[string]any{
				"targets": "192.168.1.1,192.168.1.2",
				"ports":   "22,443",
			},
			expectKeys: []string{"targets", "ports"},
		},
		{
			name: "supplychain",
			cliFlags: map[string]any{
				"mode": "generate",
				"path": supplychainRoot,
				"type": "json",
			},
			remoteFlags: map[string]any{
				"mode": "generate",
				"path": supplychainRoot,
				"type": "json",
			},
			expectKeys: []string{"mode", "path", "type"},
		},
		{
			name: "baseline",
			cliFlags: map[string]any{
				"scope":           "os",
				"baseline-config": baselineCfg,
			},
			remoteFlags: map[string]any{
				"scope":           "os",
				"baseline-config": baselineCfg,
			},
			expectKeys: []string{"scope", "baseline-config"},
		},
		{
			name: "audit",
			cliFlags: map[string]any{
				"scope": "system",
			},
			remoteFlags: map[string]any{
				"scope": "system",
			},
			expectKeys: []string{"scope"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cliReq := tasks.TaskRequest{
				Config:     cfg,
				Flags:      cloneFlags(tc.cliFlags),
				JSONOutput: true,
				Quiet:      false,
			}
			cliReq.ApplyDefaults(tc.name)
			if err := tasks.ValidateRequest(tc.name, &cliReq); err != nil {
				t.Fatalf("CLI validation failed: %v", err)
			}

			payload := map[string]any{
				"flags": cloneFlags(tc.remoteFlags),
				"json":  true,
				"quiet": true,
			}
			remoteReq := tasks.TaskRequest{
				Config: cfg,
				Flags:  make(map[string]any),
				Quiet:  true,
			}
			applyRemotePayload(&remoteReq, payload)
			remoteReq.ApplyDefaults(tc.name)
			if err := tasks.ValidateRequest(tc.name, &remoteReq); err != nil {
				t.Fatalf("remote validation failed: %v", err)
			}

			if remoteReq.Profile != cliReq.Profile {
				t.Fatalf("profile mismatch: cli=%s remote=%s", cliReq.Profile, remoteReq.Profile)
			}
			if !remoteReq.Quiet {
				t.Fatalf("remote request should force quiet mode")
			}
			if !remoteReq.JSONOutput {
				t.Fatalf("remote request should inherit json output flag")
			}

			for _, key := range tc.expectKeys {
				cliVal, cliOk := cliReq.Flags[key]
				remoteVal, remoteOk := remoteReq.Flags[key]
				if !cliOk || !remoteOk {
					t.Fatalf("missing expected flag %q (cli ok=%v remote ok=%v)", key, cliOk, remoteOk)
				}
				if cliVal != remoteVal {
					t.Fatalf("flag %q mismatch: cli=%v remote=%v", key, cliVal, remoteVal)
				}
			}
		})
	}
}

func TestApplyRemotePayloadSetsDebug(t *testing.T) {
	req := tasks.TaskRequest{}
	payload := map[string]any{"debug": true}
	applyRemotePayload(&req, payload)
	if !req.Debug {
		t.Fatalf("expected debug flag from payload")
	}
	flagPayload := map[string]any{"flags": map[string]any{"debug": "true"}}
	req = tasks.TaskRequest{}
	applyRemotePayload(&req, flagPayload)
	if !req.Debug {
		t.Fatalf("expected debug flag from flags")
	}
}
