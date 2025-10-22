package assets

import (
	"net"
	"testing"
)

func TestFormatLocalNetworks(t *testing.T) {
	networks := []LocalNetwork{
		{Interface: "eth0", CIDR: "192.168.1.0/24"},
		{Interface: "wlan0", CIDR: "10.0.0.0/24"},
	}
	got := FormatLocalNetworks(networks)
	want := "eth0:192.168.1.0/24, wlan0:10.0.0.0/24"
	if got != want {
		t.Fatalf("expected %s, got %s", want, got)
	}
}

func TestParseIPv4(t *testing.T) {
	ipNet := &net.IPNet{IP: net.ParseIP("192.168.1.10"), Mask: net.CIDRMask(24, 32)}
	ip, cidr := parseIPv4(ipNet)
	if ip == nil || ip.String() != "192.168.1.10" {
		t.Fatalf("unexpected ip result: %v", ip)
	}
	if cidr == nil || cidr.IP.String() != "192.168.1.0" {
		t.Fatalf("unexpected cidr: %v", cidr)
	}

	addr := &net.IPAddr{IP: net.ParseIP("10.0.0.5")}
	ip, cidr = parseIPv4(addr)
	if ip == nil || cidr == nil {
		t.Fatalf("expected non-nil results for IPAddr")
	}
}
