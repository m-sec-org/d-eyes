package reporters

import (
	"strings"
	"testing"
	"time"
)

func sampleHosts() []HostInfo {
	return []HostInfo{
		{IP: "10.0.0.1", Hostname: "host-a", Status: "up", OSType: "linux", OSConfidence: 0.8, DetectedBy: "nmap", DetectTime: time.Date(2025, 1, 1, 10, 0, 0, 0, time.UTC)},
		{IP: "10.0.0.2", Hostname: "host-b", Status: "down", OSType: "windows", DetectTime: time.Date(2025, 1, 1, 11, 0, 0, 0, time.UTC)},
	}
}

func samplePorts() []PortInfo {
	return []PortInfo{
		{Port: 22, Protocol: "tcp", Status: "open", Service: "ssh", Confidence: 0.9, Metadata: map[string]string{"http.server": "nginx"}, Timestamp: time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)},
		{Port: 80, Protocol: "tcp", Status: "filtered", Service: "http", Banner: "Apache", Timestamp: time.Date(2025, 1, 1, 12, 5, 0, 0, time.UTC)},
	}
}

func TestJSONFormatterOutputsJSON(t *testing.T) {
	formatter := NewJSONFormatter()
	hostsJSON, err := formatter.FormatHosts(sampleHosts())
	if err != nil || !strings.Contains(hostsJSON, "host-a") {
		t.Fatalf("expected hosts JSON: %v %s", err, hostsJSON)
	}
	portsJSON, err := formatter.FormatPorts(samplePorts())
	if err != nil || !strings.Contains(portsJSON, "ssh") {
		t.Fatalf("expected ports JSON")
	}
	result, err := formatter.FormatScanResult(ScanResult{Target: "10.0.0.1"})
	if err != nil || !strings.Contains(result, "10.0.0.1") {
		t.Fatalf("expected scan result JSON")
	}
}

func TestTableFormatterHandlesEmptyData(t *testing.T) {
	formatter := NewTableFormatter(false)
	emptyHosts, err := formatter.FormatHosts(nil)
	if err != nil || emptyHosts != "未发现活跃主机" {
		t.Fatalf("unexpected empty host output: %s", emptyHosts)
	}
	emptyPorts, err := formatter.FormatPorts(nil)
	if err != nil || emptyPorts != "未发现开放端口" {
		t.Fatalf("unexpected empty port output")
	}
}

func TestTableFormatterRendersRows(t *testing.T) {
	formatter := NewTableFormatter(true)
	hostsText, err := formatter.FormatHosts(sampleHosts())
	if err != nil || !strings.Contains(hostsText, "10.0.0.1") {
		t.Fatalf("expected table host output")
	}
	portsText, err := formatter.FormatPorts(samplePorts())
	if err != nil || !strings.Contains(portsText, "22") {
		t.Fatalf("expected table port output")
	}
}
