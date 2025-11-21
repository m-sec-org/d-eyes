package utils

import "testing"

func TestParsePortRangeAndServices(t *testing.T) {
	ports, err := ParsePortRange("22,80,100-102")
	if err != nil {
		t.Fatalf("ParsePortRange failed: %v", err)
	}
	if len(ports) != 5 || ports[0] != 22 || ports[len(ports)-1] != 102 {
		t.Fatalf("unexpected ports: %v", ports)
	}
	if _, err := ParsePortRange("bad-range"); err == nil {
		t.Fatalf("expected error for invalid input")
	}
	if !IsWellKnownPort(80) || !IsRegisteredPort(8080) || !IsDynamicPort(60000) {
		t.Fatalf("port classification incorrect")
	}
	if service := GetServiceByPort(22); service != "ssh" {
		t.Fatalf("expected ssh, got %s", service)
	}
}

func TestCommonPortHelpers(t *testing.T) {
	cp := GetCommonPorts()
	if len(cp) != len(CommonPorts) {
		t.Fatalf("GetCommonPorts should return copy")
	}
	cp[0] = 9999
	if cp[0] == CommonPorts[0] {
		t.Fatalf("copy must be independent")
	}
	if len(GetWellKnownPorts()) != 1023 {
		t.Fatalf("unexpected well-known count")
	}
	if len(GetRegisteredPorts()) != 49151-1024+1 {
		t.Fatalf("unexpected registered count")
	}
	if len(GetDynamicPorts()) != 65535-49152+1 {
		t.Fatalf("unexpected dynamic count")
	}
}
