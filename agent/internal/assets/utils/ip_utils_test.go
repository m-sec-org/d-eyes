package utils

import (
	"net"
	"testing"
)

func TestParseCIDRAndGenerateRange(t *testing.T) {
	_, ipnet, err := ParseCIDR("192.168.1.0/30")
	if err != nil {
		t.Fatalf("ParseCIDR failed: %v", err)
	}
	ips := GenerateIPRange(ipnet)
	if len(ips) != 4 {
		t.Fatalf("expected 4 ips, got %d", len(ips))
	}
	if !ips[0].Equal(net.ParseIP("192.168.1.0")) {
		t.Fatalf("unexpected first ip")
	}
}

func TestIncrementIP(t *testing.T) {
	ip := net.ParseIP("192.168.1.255")
	next := incrementIP(ip)
	if !next.Equal(net.ParseIP("192.168.2.0")) {
		t.Fatalf("incrementIP unexpected: %s", next)
	}
}

func TestPrivateLoopbackDetection(t *testing.T) {
	if !IsPrivateIP(net.ParseIP("10.0.0.1")) {
		t.Fatalf("expected private ip")
	}
	if !IsLoopbackIP(net.ParseIP("127.0.0.1")) {
		t.Fatalf("expected loopback")
	}
}

func TestGetIPFromTarget(t *testing.T) {
	ip, err := GetIPFromTarget("8.8.8.8")
	if err != nil || !ip.Equal(net.ParseIP("8.8.8.8")) {
		t.Fatalf("expected to parse ip")
	}
	if _, err := GetIPFromTarget("invalid"); err == nil {
		t.Fatalf("expected error")
	}
}
