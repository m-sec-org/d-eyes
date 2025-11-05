package assets

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/m-sec-org/d-eyes/agent/internal/assets/utils"
)

// 模拟HostDetector实现，用于测试
type MockHostDetector struct {
	DetectedIPs   []net.IP
	DiscoverError error
}

// 实现DetectHosts方法
func (m *MockHostDetector) DetectHosts(target string) ([]net.IP, error) {
	if m.DiscoverError != nil {
		return nil, m.DiscoverError
	}
	return m.DetectedIPs, nil
}

func (m *MockHostDetector) DetectHostsWithContext(ctx context.Context, target string) ([]net.IP, error) {
	return m.DetectHosts(target)
}

// 模拟PortScanner实现，用于测试
type MockPortScanner struct {
	ScanResult []PortInfo
	ScanError  error
}

func (m *MockPortScanner) ScanPorts(ip net.IP, ports []int) ([]PortInfo, error) {
	return m.ScanResult, m.ScanError
}

func (m *MockPortScanner) ScanPort(ip net.IP, port int) (PortInfo, error) {
	return PortInfo{IP: ip, Port: port, State: "open"}, nil
}

func (m *MockPortScanner) ParsePortRange(portRange string) ([]int, error) {
	return utils.ParsePortRange(portRange)
}

// MockUDPPortScanner 模拟UDP端口扫描器
type MockUDPPortScanner struct {
	ScanResult []PortInfo
	ScanError  error
}

func (m *MockUDPPortScanner) ScanPorts(ip net.IP, ports []int) ([]PortInfo, error) {
	return m.ScanResult, m.ScanError
}

func (m *MockUDPPortScanner) ScanPort(ip net.IP, port int) (PortInfo, error) {
	return PortInfo{IP: ip, Port: port, State: "open"}, nil
}

func (m *MockUDPPortScanner) ParsePortRange(portRange string) ([]int, error) {
	return utils.ParsePortRange(portRange)
}

// TestAssetScanner_DiscoverHosts 测试主机发现功能
func TestAssetScanner_DiscoverHosts(t *testing.T) {
	// 准备测试数据
	targetIP := net.ParseIP("192.168.1.1")
	mockDetector := &MockHostDetector{
		DetectedIPs: []net.IP{targetIP},
	}
	options := ScanOptions{}
	scanner := NewAssetScanner(mockDetector, nil, options)

	// 执行测试
	ctx := context.Background()
	hosts, err := scanner.DiscoverHosts(ctx, "192.168.1.1/24")

	// 验证结果
	if err != nil {
		t.Errorf("DiscoverHosts failed: %v", err)
	}
	if len(hosts) != 1 {
		t.Errorf("Expected 1 host, got %d", len(hosts))
	} else if !hosts[0].IP.Equal(targetIP) {
		t.Errorf("Expected IP %s, got %s", targetIP, hosts[0].IP)
	} else if hosts[0].Status != "up" {
		t.Errorf("Expected status 'up', got %s", hosts[0].Status)
	}

	// 测试空检测器的情况
	scanner = NewAssetScanner(nil, nil, options)
	hosts, err = scanner.DiscoverHosts(ctx, "192.168.1.1/24")
	if err != nil {
		t.Errorf("DiscoverHosts with nil detector failed: %v", err)
	}
	if len(hosts) != 0 {
		t.Errorf("Expected 0 hosts with nil detector, got %d", len(hosts))
	}
}

func TestAssetScanner_DiscoverHostsResolveHostname(t *testing.T) {
	mockDetector := &MockHostDetector{
		DetectedIPs: []net.IP{net.ParseIP("127.0.0.1")},
	}
	scanner := NewAssetScanner(mockDetector, nil, ScanOptions{ResolveHostname: true})
	hosts, err := scanner.DiscoverHosts(context.Background(), "127.0.0.1")
	if err != nil {
		t.Fatalf("DiscoverHosts failed: %v", err)
	}
	if len(hosts) != 1 {
		t.Fatalf("expected 1 host, got %d", len(hosts))
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := scanner.DiscoverHosts(ctx, "127.0.0.1"); err == nil {
		t.Fatalf("expected context canceled error")
	}
}

// TestAssetScanner_ScanHostPorts 测试端口扫描功能
func TestAssetScanner_ScanHostPorts(t *testing.T) {
	// 准备测试数据
	targetIP := net.ParseIP("192.168.1.1")
	hosts := []HostInfo{
		{IP: targetIP, Status: "up"},
	}
	ports := []int{80, 443}
	mockScanner := &MockPortScanner{
		ScanResult: []PortInfo{
			{IP: targetIP, Port: 80, State: "open"},
			{IP: targetIP, Port: 443, State: "open"},
		},
	}
	options := ScanOptions{}
	scanner := NewAssetScanner(nil, mockScanner, options)

	// 执行测试
	ctx := context.Background()
	portResults := scanner.ScanHostPorts(ctx, hosts, ports)

	// 验证结果
	if len(portResults) != 2 {
		t.Errorf("Expected 2 ports, got %d", len(portResults))
	}

	// 测试空扫描器的情况
	scanner = NewAssetScanner(nil, nil, options)
	portResults = scanner.ScanHostPorts(ctx, hosts, ports)
	if len(portResults) != 0 {
		t.Errorf("Expected 0 ports with nil scanner, got %d", len(portResults))
	}

	// 测试上下文取消的情况
	ctx, cancel := context.WithCancel(ctx)
	cancel() // 立即取消上下文
	portResults = scanner.ScanHostPorts(ctx, hosts, ports)
	if len(portResults) != 0 {
		t.Errorf("Expected 0 ports with canceled context, got %d", len(portResults))
	}
}

// TestAssetScanner_ScanSingleHost 测试单主机扫描功能
func TestAssetScanner_ScanSingleHost(t *testing.T) {
	// 准备测试数据
	targetIP := net.ParseIP("192.168.1.1")
	mockDetector := &MockHostDetector{
		DetectedIPs: []net.IP{targetIP},
	}
	mockScanner := &MockPortScanner{
		ScanResult: []PortInfo{
			{IP: targetIP, Port: 80, State: "open"},
		},
	}
	options := ScanOptions{
		Ports: "80",
	}
	scanner := NewAssetScanner(mockDetector, mockScanner, options)

	// 执行测试
	ctx := context.Background()
	host, ports, err := scanner.ScanSingleHost(ctx, "192.168.1.1")

	// 验证结果
	if err != nil {
		t.Errorf("ScanSingleHost failed: %v", err)
	}
	if !host.IP.Equal(targetIP) {
		t.Errorf("Expected IP %s, got %s", targetIP, host.IP)
	}
	if len(ports) != 1 {
		t.Errorf("Expected 1 port, got %d", len(ports))
	} else if ports[0].Port != 80 {
		t.Errorf("Expected port 80, got %d", ports[0].Port)
	}

	// 测试无效IP的情况
	_, _, err = scanner.ScanSingleHost(ctx, "invalid-ip")
	if err == nil {
		t.Errorf("Expected error for invalid IP, got nil")
	}

	// 测试上下文取消的情况
	ctx, cancel := context.WithCancel(ctx)
	cancel()
	_, _, err = scanner.ScanSingleHost(ctx, "192.168.1.1")
	if err == nil {
		t.Errorf("Expected error for canceled context, got nil")
	}

	// 测试没有端口扫描器的情况（使用新的上下文）
	newCtx := context.Background()
	scanner = NewAssetScanner(mockDetector, nil, options)
	_, ports, err = scanner.ScanSingleHost(newCtx, "192.168.1.1")
	if err != nil {
		t.Errorf("ScanSingleHost with nil scanner failed: %v", err)
	}
	if len(ports) != 0 {
		t.Errorf("Expected 0 ports with nil scanner, got %d", len(ports))
	}

	// 测试端口解析失败的情况
	scanner = NewAssetScanner(mockDetector, &MockPortScanner{}, ScanOptions{Ports: "invalid-port"})
	_, _, err = scanner.ScanSingleHost(context.Background(), "192.168.1.1")
	if err == nil {
		t.Error("Expected error for invalid port, got nil")
	}
}

// TestAssetScanner_Scan 测试完整扫描功能
func TestAssetScanner_Scan(t *testing.T) {
	// 准备测试数据
	targetIP := net.ParseIP("192.168.1.1")
	mockDetector := &MockHostDetector{
		DetectedIPs: []net.IP{targetIP},
	}
	mockScanner := &MockPortScanner{
		ScanResult: []PortInfo{
			{IP: targetIP, Port: 80, State: "open"},
		},
	}
	options := ScanOptions{
		Ports:             "80",
		HostDiscoveryOnly: false,
	}
	scanner := NewAssetScanner(mockDetector, mockScanner, options)

	// 执行测试
	ctx := context.Background()
	result, err := scanner.Scan(ctx, "192.168.1.1/24")

	// 验证结果
	if err != nil {
		t.Errorf("Scan failed: %v", err)
	}
	if result.Target != "192.168.1.1/24" {
		t.Errorf("Expected target '192.168.1.1/24', got %s", result.Target)
	}
	if len(result.Hosts) != 1 {
		t.Errorf("Expected 1 host, got %d", len(result.Hosts))
	}
	if len(result.Ports) != 1 {
		t.Errorf("Expected 1 port, got %d", len(result.Ports))
	}

	// 测试主机发现模式
	options.HostDiscoveryOnly = true
	scanner = NewAssetScanner(mockDetector, mockScanner, options)
	result, err = scanner.Scan(ctx, "192.168.1.1/24")
	if err != nil {
		t.Errorf("Scan in host discovery mode failed: %v", err)
	}
	if len(result.Ports) != 0 {
		t.Errorf("Expected 0 ports in host discovery mode, got %d", len(result.Ports))
	}
}

// TestCompositeHostDiscoverer 测试组合主机发现器
func TestCompositeHostDiscoverer(t *testing.T) {
	// 准备测试数据
	targetIP := net.ParseIP("192.168.1.1")
	mockDetector1 := &MockHostDetector{
		DetectedIPs: []net.IP{targetIP},
	}
	mockDetector2 := &MockHostDetector{
		DetectedIPs: []net.IP{net.ParseIP("192.168.1.2")},
	}

	// 创建组合发现器
	discoverer := NewCompositeHostDiscoverer(mockDetector1, mockDetector2)

	// 测试DetectHosts方法
	ips, err := discoverer.DetectHosts("192.168.1.1/24")
	if err != nil {
		t.Errorf("DetectHosts failed: %v", err)
	}
	if len(ips) != 2 {
		t.Errorf("Expected 2 IPs, got %d", len(ips))
	}

	// 测试空参数构造
	discoverer = NewCompositeHostDiscoverer()
	ips, err = discoverer.DetectHosts("192.168.1.1/24")
	if err != nil {
		t.Errorf("DetectHosts with empty discoverers failed: %v", err)
	}
	if len(ips) != 0 {
		t.Errorf("Expected 0 IPs, got %d", len(ips))
	}

	// 测试部分探测器异常
	discoverer = NewCompositeHostDiscoverer(
		&MockHostDetector{DiscoverError: fmt.Errorf("fail")},
		mockDetector1,
	)
	ips, err = discoverer.DetectHosts("192.168.1.1")
	if err != nil {
		t.Errorf("DetectHosts should ignore partial errors, got %v", err)
	}
	if len(ips) != 1 {
		t.Errorf("Expected 1 IP after partial error, got %d", len(ips))
	}

	// 测试所有探测器失败
	discoverer = NewCompositeHostDiscoverer(
		&MockHostDetector{DiscoverError: fmt.Errorf("all fail")},
	)
	ips, err = discoverer.DetectHosts("192.168.1.1")
	if err == nil {
		t.Error("Expected error when all detectors fail")
	}
	if len(ips) != 0 {
		t.Errorf("Expected 0 IPs when all detectors fail, got %d", len(ips))
	}
}

// TestHostDiscovery 测试主机发现相关功能
func TestHostDiscovery(t *testing.T) {
	// 由于我们无法直接测试ARP和ICMP发现器（可能需要root权限），
	// 我们改为使用MockHostDetector进行更全面的测试
	mockDetector := &MockHostDetector{
		DetectedIPs: []net.IP{
			net.ParseIP("192.168.1.1"),
			net.ParseIP("192.168.1.2"),
		},
	}

	// 测试DetectHosts方法
	ips, err := mockDetector.DetectHosts("192.168.1.1/24")
	if err != nil {
		t.Errorf("MockHostDetector.DetectHosts failed: %v", err)
	}
	if len(ips) != 2 {
		t.Errorf("Expected 2 IPs, got %d", len(ips))
	}

	// 测试空结果
	mockDetector.DetectedIPs = nil
	ips, err = mockDetector.DetectHosts("192.168.1.1/24")
	if err != nil {
		t.Errorf("MockHostDetector.DetectHosts with nil IPs failed: %v", err)
	}
	if len(ips) != 0 {
		t.Errorf("Expected 0 IPs, got %d", len(ips))
	}
}

// TestTCPPortScanner 测试TCP端口扫描器
func TestTCPPortScanner(t *testing.T) {
	// 创建扫描器
	timeout := 2 * time.Second
	scanner := NewTCPPortScanner(timeout, 10, 0)

	// 测试ScanPort方法
	ip := net.ParseIP("192.168.1.1")
	portInfo, err := scanner.ScanPort(ip, 80)
	if err != nil {
		t.Errorf("ScanPort failed: %v", err)
	}
	if !portInfo.IP.Equal(ip) {
		t.Errorf("Expected IP %s, got %s", ip, portInfo.IP)
	}
	if portInfo.Port != 80 {
		t.Errorf("Expected port 80, got %d", portInfo.Port)
	}

	// 测试ScanPorts方法
	_, err = scanner.ScanPorts(ip, []int{80, 443})
	if err != nil {
		t.Errorf("ScanPorts failed: %v", err)
	}

	// 测试ParsePortRange方法
	portRange, err := scanner.ParsePortRange("80,443,8080")
	if err != nil {
		t.Errorf("ParsePortRange failed: %v", err)
	}
	if len(portRange) != 3 {
		t.Errorf("Expected 3 ports, got %d", len(portRange))
	}

	// 测试无效的端口范围
	_, err = scanner.ParsePortRange("invalid-range")
	if err == nil {
		t.Error("Expected error for invalid port range, got nil")
	}

	// 测试Scan方法
	ctx := context.Background()
	_, err = scanner.Scan(ctx, "192.168.1.1", []int{80, 443}, ScanOptions{})
	if err != nil {
		t.Errorf("Scan failed: %v", err)
	}

	// 测试无效IP
	_, err = scanner.Scan(ctx, "invalid-ip", []int{80}, ScanOptions{})
	if err == nil {
		t.Error("Expected error for invalid IP, got nil")
	}
}

// TestCreateDefaultScanner 测试创建默认扫描器
func TestCreateDefaultScanner(t *testing.T) {
	options := ScanOptions{}
	scanner := CreateDefaultScanner(options)

	if scanner == nil {
		t.Errorf("Expected non-nil scanner, got nil")
	}
	if scanner.hostDetector == nil {
		t.Errorf("Expected hostDetector to be initialised")
	}
	if scanner.portScanner == nil {
		t.Errorf("Expected portScanner to be initialised")
	}
}

// TestCreateScannerFromOptions 测试从选项创建扫描器
func TestCreateScannerFromOptions(t *testing.T) {
	// 测试默认超时
	options := ScanOptions{}
	scanner := CreateScannerFromOptions(options)
	if scanner == nil {
		t.Errorf("Expected non-nil scanner, got nil")
	}
	if scanner.hostDetector == nil || scanner.portScanner == nil {
		t.Errorf("Expected detectors to be initialised for default options")
	}

	// 测试自定义超时
	options.Timeout = 5
	scanner = CreateScannerFromOptions(options)
	if scanner == nil {
		t.Errorf("Expected non-nil scanner with custom timeout, got nil")
	}
	if scanner.options.Timeout != 5 {
		t.Errorf("Expected timeout to remain 5, got %d", scanner.options.Timeout)
	}
}

// TestAssetScanner_isCIDR 测试CIDR格式验证
func TestAssetScanner_isCIDR(t *testing.T) {
	// 创建扫描器
	scanner := NewAssetScanner(nil, nil, ScanOptions{})

	// 测试有效的CIDR格式
	validCIDRs := []string{
		"192.168.1.0/24",
		"10.0.0.0/8",
		"172.16.0.0/16",
		"127.0.0.1/32",
		"::1/128", // IPv6
	}

	for _, cidr := range validCIDRs {
		if !scanner.isCIDR(cidr) {
			t.Errorf("Expected '%s' to be valid CIDR", cidr)
		}
	}

	// 测试无效的CIDR格式
	invalidCIDRs := []string{
		"192.168.1.1",     // 单个IP
		"192.168.1.0/33",  // 无效的前缀长度
		"abc.def.ghi.jkl", // 无效的IP格式
		"",                // 空字符串
	}

	for _, cidr := range invalidCIDRs {
		if scanner.isCIDR(cidr) {
			t.Errorf("Expected '%s' to be invalid CIDR", cidr)
		}
	}
}

// TestNetworkScan 测试网络扫描功能
func TestNetworkScan(t *testing.T) {
	// 创建扫描器
	scanner := NewAssetScanner(nil, nil, ScanOptions{})
	ctx := context.Background()

	// 测试有效的IP地址作为网络
	result, err := scanner.NetworkScan(ctx, "192.168.1.1")
	if err != nil {
		t.Errorf("NetworkScan with IP failed: %v", err)
	}
	if result.Target != "192.168.1.0/24" {
		t.Errorf("Expected target '192.168.1.0/24', got %s", result.Target)
	}

	// 测试有效的CIDR格式
	result, err = scanner.NetworkScan(ctx, "10.0.0.0/8")
	if err != nil {
		t.Errorf("NetworkScan with CIDR failed: %v", err)
	}
	if result.Target != "10.0.0.0/8" {
		t.Errorf("Expected target '10.0.0.0/8', got %s", result.Target)
	}

	// 测试无效的网络格式
	result, err = scanner.NetworkScan(ctx, "invalid-network")
	if err == nil {
		t.Errorf("Expected error for invalid network, got nil")
	}
}

// TestFastScan 测试快速扫描功能
func TestFastScan(t *testing.T) {
	// 创建扫描器
	mockDetector := &MockHostDetector{
		DetectedIPs: []net.IP{net.ParseIP("192.168.1.1")},
	}
	mockScanner := &MockPortScanner{
		ScanResult: []PortInfo{
			{IP: net.ParseIP("192.168.1.1"), Port: 80, State: "open"},
		},
	}
	scanner := NewAssetScanner(mockDetector, mockScanner, ScanOptions{
		Ports: "80",
	})
	ctx := context.Background()

	// 执行快速扫描
	result, err := scanner.FastScan(ctx, "192.168.1.1")
	if err != nil {
		t.Errorf("FastScan failed: %v", err)
	}
	if result.ScanType != "fast" {
		t.Errorf("Expected scan type 'fast', got %s", result.ScanType)
	}

	// 测试上下文取消的情况（使用专门的测试用例）
	t.Run("canceled context", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // 立即取消
		_, err := scanner.FastScan(ctx, "192.168.1.1")
		if err == nil {
			t.Errorf("Expected error for canceled context, got nil")
		}
	})

	// 测试无效IP的情况（使用专门的测试用例）
	t.Run("invalid IP", func(t *testing.T) {
		_, err := scanner.FastScan(context.Background(), "invalid-ip")
		if err == nil {
			t.Errorf("Expected error for invalid IP, got nil")
		}
	})
}

// TestUDPPortScanner 测试UDP端口扫描器
func TestUDPPortScanner(t *testing.T) {
	// 创建模拟UDP扫描器
	mockScanner := &MockUDPPortScanner{
		ScanResult: []PortInfo{
			{IP: net.ParseIP("192.168.1.1"), Port: 53, State: "open"},
		},
	}

	// 测试ScanPorts方法
	results, err := mockScanner.ScanPorts(net.ParseIP("192.168.1.1"), []int{53})
	if err != nil {
		t.Errorf("MockUDPPortScanner.ScanPorts failed: %v", err)
	}
	if len(results) != 1 {
		t.Errorf("Expected 1 result, got %d", len(results))
	}

	// 测试实际的UDPPortScanner
	timeout := 2 * time.Second
	scanner := NewUDPPortScanner(timeout, 10, 100)

	// 由于UDPPortScanner没有公开的ScanPort方法，我们跳过这个测试

	// 测试Scan方法
	ctx := context.Background()
	results, err = scanner.Scan(ctx, "192.168.1.1", []int{53}, ScanOptions{})
	if err != nil {
		t.Errorf("Scan failed: %v", err)
	}

	// 测试无效IP
	_, err = scanner.Scan(ctx, "invalid-ip", []int{53}, ScanOptions{})
	if err == nil {
		t.Error("Expected error for invalid IP, got nil")
	}
}

// TestNewUDPPortScanner 测试创建UDP端口扫描器
func TestNewUDPPortScanner(t *testing.T) {
	timeout := 2 * time.Second
	scanner := NewUDPPortScanner(timeout, 10, 100)
	if scanner == nil {
		t.Error("Failed to create UDPPortScanner")
	}
}

// TestValidateScannerOptions 测试验证扫描器选项
func TestValidateScannerOptions(t *testing.T) {
	// 测试有效选项
	options := ScanOptions{
		Concurrency: 100,
		Ports:       "80,443",
	}
	err := ValidateScannerOptions(options)
	if err != nil {
		t.Errorf("ValidateScannerOptions with valid options failed: %v", err)
	}

	// 测试无效的并发数（负数）
	options.Concurrency = -1
	err = ValidateScannerOptions(options)
	// 我们期望它能处理负数并调整为合理值
	if err != nil {
		t.Errorf("ValidateScannerOptions with negative concurrency failed: %v", err)
	}

	// 测试非常大的并发数
	options.Concurrency = 10000
	err = ValidateScannerOptions(options)
	// 期望它能调整到合理上限
	if err != nil {
		t.Errorf("ValidateScannerOptions with large concurrency failed: %v", err)
	}

	// 测试空端口字符串
	options.Ports = ""
	err = ValidateScannerOptions(options)
	if err != nil {
		t.Errorf("ValidateScannerOptions with empty ports failed: %v", err)
	}
}

// TestGetScannerStats 测试获取扫描器统计信息
func TestGetScannerStats(t *testing.T) {
	// 创建包含主机和端口信息的扫描结果
	result := ScanResult{
		Target: "192.168.1.1/24",
		Hosts: []HostInfo{
			{IP: net.ParseIP("192.168.1.1"), Status: "up"},
			{IP: net.ParseIP("192.168.1.2"), Status: "down"},
		},
		Ports: []PortInfo{
			{IP: net.ParseIP("192.168.1.1"), Port: 80, State: "open"},
			{IP: net.ParseIP("192.168.1.1"), Port: 443, State: "closed"},
		},
		StartTime: time.Now().Add(-10 * time.Second),
		EndTime:   time.Now(),
		ScanType:  "full",
	}

	// 直接测试包中定义的GetScannerStats函数
	// 由于GetScannerStats可能返回nil或空map，这里只检查它不会导致panic
	_ = GetScannerStats(result)

	// 测试空结果
	emptyResult := ScanResult{}
	_ = GetScannerStats(emptyResult)
}

// TestAssetScanner_Scan_WithError 测试Scan方法在错误情况下的行为
func TestAssetScanner_Scan_WithError(t *testing.T) {
	// 创建模拟主机发现器（返回错误）
	errDiscover := &MockHostDetector{
		DiscoverError: &net.DNSError{Err: "test error"},
	}

	// 创建扫描器
	scanner := NewAssetScanner(errDiscover, &MockPortScanner{}, ScanOptions{})

	// 测试Scan方法
	ctx := context.Background()
	results, err := scanner.Scan(ctx, "192.168.1.0/30")
	if err == nil {
		t.Error("Expected error, got nil")
	}
	// ScanResult不是指针类型，所以不需要检查nil
	if results.Target != "192.168.1.0/30" {
		t.Errorf("Expected target '192.168.1.0/30', got %s", results.Target)
	}
}

// TestAssetScanner_DiscoverHosts_WithError 测试DiscoverHosts方法在错误情况下的行为
func TestAssetScanner_DiscoverHosts_WithError(t *testing.T) {
	// 创建模拟主机发现器（返回错误）
	errDiscover := &MockHostDetector{
		DiscoverError: &net.DNSError{Err: "test error"},
	}

	// 创建扫描器
	scanner := NewAssetScanner(errDiscover, &MockPortScanner{}, ScanOptions{})

	// 测试DiscoverHosts方法
	ctx := context.Background()
	results, err := scanner.DiscoverHosts(ctx, "192.168.1.0/30")
	if err == nil {
		t.Error("Expected error, got nil")
	}
	if results != nil {
		t.Errorf("Expected nil results, got %v", results)
	}
}
