//go:build !noskip

package assets

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/m-sec-org/d-eyes/agent/internal/assets/utils"
)

// TCPPortScanner 基于TCP的端口扫描实现
type TCPPortScanner struct {
	timeout time.Duration
	workers int
	rate    int
}

// ScanPorts 扫描目标主机的端口，实现PortScanner接口
func (s *TCPPortScanner) ScanPorts(ip net.IP, ports []int) ([]PortInfo, error) {
	if ip == nil {
		return nil, fmt.Errorf("invalid ip address")
	}
	if len(ports) == 0 {
		return []PortInfo{}, nil
	}

	workerCount := s.workers
	if workerCount <= 0 {
		workerCount = 5
	}

	results := make([]PortInfo, 0, len(ports))
	var mu sync.Mutex
	var wg sync.WaitGroup
	portChan := make(chan int)

	go func() {
		defer close(portChan)
		var ticker *time.Ticker
		if s.rate > 0 {
			interval := time.Second / time.Duration(s.rate)
			if interval <= 0 {
				interval = time.Millisecond
			}
			ticker = time.NewTicker(interval)
			defer ticker.Stop()
		}
		for _, port := range ports {
			if ticker != nil {
				<-ticker.C
			}
			portChan <- port
		}
	}()

	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for port := range portChan {
				info, err := s.ScanPort(ip, port)
				if err != nil {
					continue
				}
				mu.Lock()
				results = append(results, info)
				mu.Unlock()
			}
		}()
	}

	wg.Wait()
	return results, nil
}

// ScanPort 扫描单个端口，实现PortScanner接口
func (s *TCPPortScanner) ScanPort(ip net.IP, port int) (PortInfo, error) {
	if ip == nil {
		return PortInfo{}, fmt.Errorf("invalid ip address")
	}
	if !utils.IsValidPort(port) {
		return PortInfo{}, fmt.Errorf("invalid port %d", port)
	}

	addr := fmt.Sprintf("%s:%d", ip.String(), port)
	state := "closed"
	conn, err := net.DialTimeout("tcp", addr, s.timeout)
	if err == nil {
		state = "open"
		_ = conn.Close()
	}
	return PortInfo{IP: ip, Port: port, State: state, Protocol: "tcp", Timestamp: time.Now()}, nil
}

// ParsePortRange 解析端口范围字符串，实现PortScanner接口
func (s *TCPPortScanner) ParsePortRange(portRange string) ([]int, error) {
	return utils.ParsePortRange(portRange)
}

// NewTCPPortScanner 创建TCP端口扫描器
func NewTCPPortScanner(timeout time.Duration, workers int, rate int) *TCPPortScanner {
	return &TCPPortScanner{
		timeout: timeout,
		workers: workers,
		rate:    rate,
	}
}

// Scan 实现PortScanner接口
func (s *TCPPortScanner) Scan(ctx context.Context, target string, ports []int, options ScanOptions) ([]PortInfo, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(ports) == 0 {
		return []PortInfo{}, nil
	}

	ip := net.ParseIP(target)
	if ip == nil {
		ips, err := net.LookupIP(target)
		if err != nil || len(ips) == 0 {
			return nil, fmt.Errorf("invalid target: %s", target)
		}
		ip = ips[0]
	}

	return s.ScanPorts(ip, ports)
}

// ServiceProbeResult describes banner probe outputs.
type ServiceProbeResult struct {
	Banner        string
	Raw           []byte
	TLSCommonName string
	TLSIssuer     string
	Metadata      map[string]string
}

// ServiceDetector 服务检测实现
type ServiceDetector struct {
	timeout  time.Duration
	protocol string
	tls      bool
}

// NewServiceDetector 创建服务检测器
func NewServiceDetector(timeout time.Duration, protocol string, tls bool) *ServiceDetector {
	return &ServiceDetector{
		timeout:  timeout,
		protocol: strings.ToLower(protocol),
		tls:      tls,
	}
}

// Detect 检测服务详情
func (d *ServiceDetector) Detect(ctx context.Context, target string, port int) (ServiceProbeResult, error) {
	result := ServiceProbeResult{
		Metadata: make(map[string]string),
	}
	addr := fmt.Sprintf("%s:%d", target, port)

	ctx, cancel := context.WithTimeout(ctx, d.timeout)
	defer cancel()

	var conn net.Conn
	var err error

	switch d.protocol {
	case "udp":
		conn, err = net.DialTimeout("udp", addr, d.timeout)
	default:
		if d.tls {
			conn, err = tls.DialWithDialer(&net.Dialer{Timeout: d.timeout}, "tcp", addr, &tls.Config{
				InsecureSkipVerify: true,
			})
		} else {
			conn, err = net.DialTimeout("tcp", addr, d.timeout)
		}
	}

	if err != nil {
		return result, err
	}
	defer conn.Close()

	if tlsConn, ok := conn.(*tls.Conn); ok {
		if err := tlsConn.Handshake(); err == nil {
			state := tlsConn.ConnectionState()
			if len(state.PeerCertificates) > 0 {
				cert := state.PeerCertificates[0]
				result.TLSCommonName = cert.Subject.CommonName
				result.TLSIssuer = cert.Issuer.CommonName
			}
		}
	}

	probe, err := d.getServiceBanner(conn, port)
	if err != nil {
		return result, err
	}
	if len(probe.Metadata) > 0 {
		for k, v := range probe.Metadata {
			result.Metadata[k] = v
		}
	}
	if probe.Banner != "" {
		result.Banner = probe.Banner
	}
	if len(probe.Raw) > 0 {
		result.Raw = probe.Raw
	}
	return result, nil
}

// getServiceBanner 获取服务Banner
func (d *ServiceDetector) getServiceBanner(conn net.Conn, port int) (ServiceProbeResult, error) {
	result := ServiceProbeResult{
		Metadata: make(map[string]string),
	}
	conn.SetDeadline(time.Now().Add(d.timeout))

	serviceName := strings.ToLower(utils.GetServiceByPort(port))

	switch serviceName {
	case "http", "https":
		host := hostFromAddr(conn.RemoteAddr())
		req := "GET / HTTP/1.1\r\nHost: " + host + "\r\nUser-Agent: d-eyes\r\nConnection: close\r\n\r\n"
		if _, err := conn.Write([]byte(req)); err != nil {
			return result, err
		}
	case "ftp":
	case "smtp":
		req := "EHLO scanner\r\n"
		if _, err := conn.Write([]byte(req)); err != nil {
			return result, err
		}
	case "redis":
		req := "*1\r\n$4\r\nINFO\r\n"
		if _, err := conn.Write([]byte(req)); err != nil {
			return result, err
		}
	}

	buffer := make([]byte, 2048)
	n, err := conn.Read(buffer)
	if err != nil && err != io.EOF {
		return result, err
	}

	if n <= 0 {
		return result, nil
	}

	raw := make([]byte, n)
	copy(raw, buffer[:n])
	result.Raw = raw
	text := string(raw)
	result.Banner = sanitizeBanner(text)

	enrichProbeMetadata(&result, serviceName, text)
	return result, nil
}

func hostFromAddr(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	return host
}

func sanitizeBanner(raw string) string {
	raw = strings.ReplaceAll(raw, "\r", "")
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	collapsed := strings.Join(strings.Fields(raw), " ")
	if len(collapsed) > 300 {
		collapsed = collapsed[:300] + "..."
	}
	return collapsed
}

func enrichProbeMetadata(result *ServiceProbeResult, serviceName string, raw string) {
	if result.Metadata == nil {
		result.Metadata = make(map[string]string)
	}
	service := serviceName
	trimmed := strings.TrimSpace(raw)
	if service == "" {
		upper := strings.ToUpper(trimmed)
		if strings.HasPrefix(upper, "HTTP/") {
			service = "http"
		}
	}
	switch service {
	case "http", "https":
		lines := strings.Split(strings.ReplaceAll(raw, "\r", ""), "\n")
		if len(lines) > 0 {
			status := strings.TrimSpace(lines[0])
			if status != "" {
				result.Metadata["http.status_line"] = status
			}
		}
		for _, line := range lines[1:] {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			if idx := strings.Index(line, ":"); idx > 0 {
				key := strings.ToLower(strings.TrimSpace(line[:idx]))
				value := strings.TrimSpace(line[idx+1:])
				if key != "" && value != "" {
					result.Metadata["http.header."+key] = value
					if key == "server" {
						result.Metadata["http.server"] = value
					}
				}
			}
		}
	case "smtp":
		result.Metadata["smtp.banner"] = sanitizeBanner(raw)
	case "redis":
		result.Metadata["redis.info"] = sanitizeBanner(raw)
	}
}

// SYNPortScanner 提供半开扫描能力（缺省回退至TCP connect）
type SYNPortScanner struct {
	fallback *TCPPortScanner
}

func NewSYNPortScanner(timeout time.Duration, workers, rate int) *SYNPortScanner {
	return &SYNPortScanner{fallback: NewTCPPortScanner(timeout, workers, rate)}
}

func (s *SYNPortScanner) ScanPorts(ip net.IP, ports []int) ([]PortInfo, error) {
	if !isPrivilegedUser() {
		return s.fallback.ScanPorts(ip, ports)
	}
	// TODO: implement raw SYN probing; currently fallback to TCP connect scanner.
	return s.fallback.ScanPorts(ip, ports)
}

func (s *SYNPortScanner) ScanPort(ip net.IP, port int) (PortInfo, error) {
	return s.fallback.ScanPort(ip, port)
}

func (s *SYNPortScanner) ParsePortRange(portRange string) ([]int, error) {
	return s.fallback.ParsePortRange(portRange)
}

// UDPPortScanner UDP端口扫描实现
type UDPPortScanner struct {
	timeout time.Duration
	workers int
	rate    int
}

// NewUDPPortScanner 创建UDP端口扫描器
func NewUDPPortScanner(timeout time.Duration, workers int, rate int) *UDPPortScanner {
	return &UDPPortScanner{
		timeout: timeout,
		workers: workers,
		rate:    rate,
	}
}

// Scan 执行UDP端口扫描
func (s *UDPPortScanner) Scan(ctx context.Context, target string, ports []int, options ScanOptions) ([]PortInfo, error) {
	var results []PortInfo
	var mu sync.Mutex
	var wg sync.WaitGroup

	ip := net.ParseIP(target)
	if ip == nil {
		ips, err := net.LookupIP(target)
		if err != nil || len(ips) == 0 {
			return nil, errors.New("无效的目标地址")
		}
		ip = ips[0]
	}

	portChan := make(chan int, len(ports))
	for _, port := range ports {
		portChan <- port
	}
	close(portChan)

	workerCount := s.workers
	if workerCount <= 0 {
		workerCount = 5
	}
	var ticker *time.Ticker
	if s.rate > 0 {
		interval := time.Second / time.Duration(s.rate)
		if interval <= 0 {
			interval = time.Millisecond
		}
		ticker = time.NewTicker(interval)
		defer ticker.Stop()
	}

	for port := range portChan {
		if ticker != nil {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-ticker.C:
			}
		} else {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			default:
			}
		}
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			portInfo, err := s.scanPort(ctx, ip, p)
			if err == nil && portInfo != nil {
				mu.Lock()
				results = append(results, *portInfo)
				mu.Unlock()
			}
		}(port)
	}

	wg.Wait()
	return results, nil
}

// ScanPorts 实现 PortScanner 接口
func (s *UDPPortScanner) ScanPorts(ip net.IP, ports []int) ([]PortInfo, error) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	return s.Scan(ctx, ip.String(), ports, ScanOptions{})
}

func (s *UDPPortScanner) scanPort(ctx context.Context, targetIP net.IP, port int) (*PortInfo, error) {
	conn, err := net.DialUDP("udp", nil, &net.UDPAddr{
		IP:   targetIP,
		Port: port,
	})
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(s.timeout))

	payload := []byte("ping")
	if _, err := conn.Write(payload); err != nil {
		return nil, err
	}

	buffer := make([]byte, 512)
	conn.SetReadDeadline(time.Now().Add(s.timeout))
	n, _, err := conn.ReadFromUDP(buffer)
	state := "open|filtered"
	if err == nil && n > 0 {
		state = "open"
	}

	return &PortInfo{
		IP:        targetIP,
		Port:      port,
		State:     state,
		Protocol:  "udp",
		Timestamp: time.Now(),
	}, nil
}

// ScanPort 实现 PortScanner 接口
func (s *UDPPortScanner) ScanPort(ip net.IP, port int) (PortInfo, error) {
	ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()
	info, err := s.scanPort(ctx, ip, port)
	if err != nil || info == nil {
		return PortInfo{}, err
	}
	return *info, nil
}

// ParsePortRange 实现 PortScanner 接口
func (s *UDPPortScanner) ParsePortRange(portRange string) ([]int, error) {
	return utils.ParsePortRange(portRange)
}
