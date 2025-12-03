package assets

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"
)

func startTestTCPServer(t *testing.T) (net.Listener, int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		if shouldSkipListen(err) {
			t.Skipf("skip host discovery tests due to listen permissions: %v", err)
		}
		t.Fatalf("failed to start test listener: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()
	return ln, port
}

func TestBasicHostDetectorDetectHosts(t *testing.T) {
	ln, port := startTestTCPServer(t)
	defer ln.Close()

	detector := NewBasicHostDetector(200*time.Millisecond, []int{port})
	hosts, err := detector.DetectHosts("127.0.0.1")
	if err != nil {
		t.Fatalf("DetectHosts returned error: %v", err)
	}
	if len(hosts) != 1 || !hosts[0].Equal(net.ParseIP("127.0.0.1")) {
		t.Fatalf("expected host 127.0.0.1, got %+v", hosts)
	}

	hosts, err = detector.DetectHosts("127.0.0.1/32")
	if err != nil {
		t.Fatalf("DetectHosts on CIDR failed: %v", err)
	}
	if len(hosts) != 1 {
		t.Fatalf("expected 1 host for /32 CIDR, got %d", len(hosts))
	}

	hosts, err = detector.DetectHosts("127.0.0.2")
	if err != nil {
		t.Fatalf("unexpected error for unreachable host: %v", err)
	}
	if len(hosts) != 0 {
		t.Fatalf("expected no reachable hosts, got %d", len(hosts))
	}

	if _, err := detector.DetectHosts("not-a-valid-target"); err == nil {
		t.Fatal("expected error for invalid target, got nil")
	}

	detector = NewBasicHostDetector(200*time.Millisecond, []int{port, -1, 70000})
	hosts, err = detector.DetectHosts("127.0.0.1")
	if err != nil || len(hosts) != 1 {
		t.Fatalf("expected host detection with filtered ports, got hosts=%v err=%v", hosts, err)
	}
}

func TestCompositeHostDiscovererBehaviour(t *testing.T) {
	ip1 := net.ParseIP("10.0.0.1")
	ip2 := net.ParseIP("10.0.0.2")

	discoverer := NewCompositeHostDiscoverer(
		&MockHostDetector{DetectedIPs: []net.IP{ip1}},
		&MockHostDetector{DetectedIPs: []net.IP{ip2}},
	)

	ips, err := discoverer.DetectHosts("10.0.0.0/30")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ips) != 2 {
		t.Fatalf("expected 2 hosts, got %d", len(ips))
	}

	discoverer = NewCompositeHostDiscoverer(
		&MockHostDetector{DiscoverError: fmt.Errorf("fail")},
	)
	if _, err := discoverer.DetectHosts("10.0.0.1"); err == nil {
		t.Fatal("expected error when all detectors fail")
	}
}

func TestCreateScannerFromOptionsIntegration(t *testing.T) {
	ln, port := startTestTCPServer(t)
	defer ln.Close()

	options := ScanOptions{
		Ports:       fmt.Sprintf("%d", port),
		Timeout:     1,
		Concurrency: 4,
	}
	scanner := CreateScannerFromOptions(options)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	result, err := scanner.Scan(ctx, "127.0.0.1/32")
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	if len(result.Hosts) != 1 {
		t.Fatalf("expected 1 host, got %d", len(result.Hosts))
	}
	if len(result.Ports) != 1 {
		t.Fatalf("expected 1 port, got %d", len(result.Ports))
	}
	if result.Ports[0].State != "open" {
		t.Fatalf("expected port to be open, got %s", result.Ports[0].State)
	}
}

func TestCreateScannerFromOptionsInvalidPortFallback(t *testing.T) {
	scanner := CreateScannerFromOptions(ScanOptions{Ports: "invalid-range", Timeout: 1})
	if scanner == nil {
		t.Fatal("expected scanner instance")
	}
	if scanner.hostDetector == nil || scanner.portScanner == nil {
		t.Fatal("expected detectors to be initialized")
	}
}
