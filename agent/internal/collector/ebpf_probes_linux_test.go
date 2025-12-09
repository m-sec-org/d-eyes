package collector

import "testing"

func TestProbeRegistryResolveCategory(t *testing.T) {
	reg := newEBPFProbeRegistry()
	probes, err := reg.Resolve([]string{"category:process"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(probes) == 0 {
		t.Fatalf("expected process probes")
	}
}

func TestProbeRegistryResolveUnknown(t *testing.T) {
	reg := newEBPFProbeRegistry()
	if _, err := reg.Resolve([]string{"unknown-probe"}); err == nil {
		t.Fatalf("expected error for unknown probe")
	}
	if _, err := reg.Resolve([]string{"category:missing"}); err == nil {
		t.Fatalf("expected error for unknown category")
	}
}
