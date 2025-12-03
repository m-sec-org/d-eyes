package assets

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

func startDummyTCPServer(t *testing.T) (net.Listener, int) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		if shouldSkipListen(err) {
			t.Skipf("skip port scanner tests due to listen permissions: %v", err)
		}
		t.Fatalf("failed to start listener: %v", err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Write([]byte("HTTP/1.1 200 OK\r\nServer: test\r\n\r\n"))
			conn.Close()
		}
	}()
	return ln, ln.Addr().(*net.TCPAddr).Port
}

func TestTCPPortScannerScanPorts(t *testing.T) {
	ln, port := startDummyTCPServer(t)
	defer ln.Close()

	scanner := NewTCPPortScanner(500*time.Millisecond, 2, 0)
	results, err := scanner.ScanPorts(net.ParseIP("127.0.0.1"), []int{port, port + 1})
	if err != nil {
		t.Fatalf("scan ports error: %v", err)
	}
	if len(results) == 0 {
		t.Fatalf("expected results")
	}
}

func TestServiceDetector(t *testing.T) {
	ln, port := startDummyTCPServer(t)
	defer ln.Close()

	detector := NewServiceDetector(500*time.Millisecond, "tcp", false)
	ctx := context.Background()
	probe, err := detector.Detect(ctx, "127.0.0.1", port)
	if err != nil {
		t.Fatalf("detect failed: %v", err)
	}
	if probe.Banner == "" {
		t.Fatalf("expected banner")
	}
	if !strings.Contains(probe.Banner, "HTTP/1.1") {
		t.Fatalf("expected banner to include HTTP status")
	}
}
