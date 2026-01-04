package assets

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/urfave/cli/v2"
)

func newCLIContext(t *testing.T, args []string) *cli.Context {
	t.Helper()
	app := cli.NewApp()
	fs := flag.NewFlagSet("assets-test", flag.ContinueOnError)
	fs.String("format", "", "")
	fs.String("output", "", "")
	fs.Bool("verbose", false, "")
	fs.Bool("color", true, "")
	fs.Bool("debug", false, "")
	fs.String("interface", "", "")
	fs.String("discovery", "", "")
	fs.String("scan-method", "", "")
	fs.String("ports", "", "")
	fs.Int("timeout", 0, "")
	fs.Int("rate", 0, "")
	fs.Int("concurrency", 0, "")
	fs.Bool("local", false, "")
	fs.Bool("arp", false, "")
	fs.Bool("hosts-only", false, "")
	fs.Bool("resolve", false, "")
	fs.Bool("banner", false, "")
	fs.Bool("service-detect", false, "")
	fs.Bool("os-detect", false, "")
	fs.Bool("include-loopback", false, "")
	fs.Int("limit", 0, "")
	if err := fs.Parse(args); err != nil {
		t.Fatalf("failed to parse flags: %v", err)
	}
	return cli.NewContext(app, fs, nil)
}

func TestNewAssetsCommand(t *testing.T) {
	cmd := NewAssetsCommand()
	if cmd == nil {
		t.Fatalf("expected command")
	}
	if len(cmd.Subcommands) != 6 {
		t.Fatalf("expected 6 subcommands, got %d", len(cmd.Subcommands))
	}
}

func TestRunScanVariants(t *testing.T) {
	port := 12345
	target := "127.0.0.1"

	mockScanner := &MockPortScanner{
		ScanResult: []PortInfo{{IP: net.ParseIP(target), Port: port, State: "open"}},
	}
	mockDetector := &MockHostDetector{DetectedIPs: []net.IP{net.ParseIP(target)}}

	SetAssetsScannerFactory(func(options ScanOptions) *AssetScanner {
		return NewAssetScanner(mockDetector, mockScanner, options)
	})
	defer SetAssetsScannerFactory(nil)

	ctx := newCLIContext(t, []string{fmt.Sprintf("--ports=%d", port), "--timeout=1", target})
	if err := runScan(ctx); err != nil {
		t.Fatalf("runScan failed: %v", err)
	}

	ctx = newCLIContext(t, []string{"--timeout=1", target})
	if err := runDiscover(ctx); err != nil {
		t.Fatalf("runDiscover failed: %v", err)
	}

	ctx = newCLIContext(t, []string{"--timeout=1", target})
	if err := runFastScan(ctx); err != nil {
		t.Fatalf("runFastScan failed: %v", err)
	}

	ctx = newCLIContext(t, []string{"--timeout=1", target})
	if err := runNetworkScan(ctx); err != nil {
		t.Fatalf("runNetworkScan failed: %v", err)
	}

	tmpDir := t.TempDir()
	output := filepath.Join(tmpDir, "result.json")
	ctx = newCLIContext(t, []string{
		fmt.Sprintf("--ports=%d", port),
		"--timeout=1",
		fmt.Sprintf("--output=%s", output),
		"--format=json",
		target,
	})
	if err := runInfo(ctx); err != nil {
		t.Fatalf("runInfo failed: %v", err)
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatalf("failed to read output file: %v", err)
	}
	if len(data) == 0 {
		t.Fatalf("expected output data")
	}
}

func TestAssetsRunnerExecuteValidation(t *testing.T) {
	runner := NewAssetsRunner(AssetsConfig{})
	err := runner.Execute(context.Background(), ScanRequest{Target: "", ScanType: "test", Options: ScanOptions{}})
	if err == nil {
		t.Fatalf("expected error for empty target")
	}
}

func TestNormalizeScanOptions(t *testing.T) {
	opts := ScanOptions{LocalScan: true}
	normalizeScanOptions(&opts)
	if opts.DiscoveryMethod != "mixed" {
		t.Fatalf("expected mixed discovery, got %s", opts.DiscoveryMethod)
	}

	opts = ScanOptions{ArpScan: true}
	normalizeScanOptions(&opts)
	if opts.DiscoveryMethod != "arp" {
		t.Fatalf("expected arp discovery when arpScan set, got %s", opts.DiscoveryMethod)
	}
	if !opts.LocalScan {
		t.Fatalf("expected localScan to be forced when arpScan is set")
	}
}

func TestRunnerOutputToFile(t *testing.T) {
	tmpDir := t.TempDir()
	output := filepath.Join(tmpDir, "result.txt")
	runner := NewAssetsRunner(AssetsConfig{
		OutputFormat: "json",
		OutputFile:   output,
		ColorOutput:  false,
	})
	runner.SetNow(func() time.Time { return time.Unix(0, 0) })

	result := ScanResult{
		Target:    "127.0.0.1",
		ScanType:  "test",
		StartTime: time.Unix(0, 0),
		EndTime:   time.Unix(1, 0),
		Hosts: []HostInfo{
			{IP: net.ParseIP("127.0.0.1"), Status: "up"},
		},
		Ports: []PortInfo{
			{IP: net.ParseIP("127.0.0.1"), Port: 80, State: "open", Protocol: "tcp"},
		},
	}

	if err := runner.outputResult(result, nil); err != nil {
		t.Fatalf("outputResult failed: %v", err)
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatalf("failed to read output file: %v", err)
	}
	if len(data) == 0 {
		t.Fatalf("expected non-empty output file")
	}
}

func TestValidationHelpers(t *testing.T) {
	if !isValidIPAddress("127.0.0.1") {
		t.Fatalf("expected valid ip")
	}
	if !isValidDomain("localhost") {
		t.Fatalf("expected single label domain to be valid")
	}
	if !isValidDomain("example.com") {
		t.Fatalf("expected valid domain")
	}
	if !isValidCIDR("127.0.0.1/32") {
		t.Fatalf("expected valid cidr")
	}
	if isValidCIDR("bad-cidr") {
		t.Fatalf("expected invalid cidr")
	}
}

func TestRunLocalScan(t *testing.T) {
	defer SetLocalNetworkDiscoverer(nil)
	SetLocalNetworkDiscoverer(func(bool) ([]LocalNetwork, error) {
		return []LocalNetwork{{Interface: "eth0", CIDR: "192.168.1.0/24", IP: net.ParseIP("192.168.1.1")}}, nil
	})

	mockScanner := &MockPortScanner{
		ScanResult: []PortInfo{{IP: net.ParseIP("192.168.1.10"), Port: 80, State: "open", Protocol: "tcp"}},
	}
	mockDetector := &MockHostDetector{DetectedIPs: []net.IP{net.ParseIP("192.168.1.10")}}

	SetAssetsScannerFactory(func(options ScanOptions) *AssetScanner {
		return NewAssetScanner(mockDetector, mockScanner, options)
	})
	defer SetAssetsScannerFactory(nil)

	ctx := newCLIContext(t, []string{"--timeout=1", "--verbose"})
	if err := runLocalScan(ctx); err != nil {
		t.Fatalf("runLocalScan failed: %v", err)
	}
}

func TestIsRootRequiredAndHelpers(t *testing.T) {
	if IsRootRequired() == isPrivilegedUser() {
		t.Fatalf("expected IsRootRequired to be the negation of isPrivilegedUser")
	}
}
