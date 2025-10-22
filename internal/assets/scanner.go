package assets

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pkg/errors"

	"github.com/m-sec-org/d-eyes/internal/assets/fingerprints"
	"github.com/m-sec-org/d-eyes/internal/assets/utils"
	"github.com/m-sec-org/d-eyes/internal/progress"
)

// AssetScanner 资产扫描器实现
type AssetScanner struct {
	hostDetector HostDetector
	portScanner  PortScanner
	options      ScanOptions
	progress     *progress.Manager
}

// NewAssetScanner 创建资产扫描器
func NewAssetScanner(hostDetector HostDetector, portScanner PortScanner, options ScanOptions) *AssetScanner {
	return &AssetScanner{
		hostDetector: hostDetector,
		portScanner:  portScanner,
		options:      options,
	}
}

// SetProgress 设置进度上报器
func (s *AssetScanner) SetProgress(p *progress.Manager) {
	s.progress = p
	if setter, ok := s.hostDetector.(interface{ SetProgress(*progress.Manager) }); ok {
		setter.SetProgress(p)
	}
}

// CreateDefaultScanner 创建默认的资产扫描器
// 注意：由于接口实现问题，这个函数暂时返回一个简化版本的扫描器
func CreateDefaultScanner(options ScanOptions) *AssetScanner {
	return CreateScannerFromOptions(options)
}

// Scan 执行完整的资产扫描
func (s *AssetScanner) Scan(ctx context.Context, target string) (ScanResult, error) {
	result := ScanResult{
		Target:    target,
		ScanType:  "comprehensive",
		Options:   s.options,
		StartTime: time.Now(),
		EndTime:   time.Now(), // 初始化结束时间
	}

	if s.progress != nil {
		s.progress.Debugf("开始扫描目标 %s", target)
	}

	// 1. 主机发现
	hosts, err := s.DiscoverHosts(ctx, target)
	if err != nil {
		return result, errors.Wrap(err, "主机发现失败")
	}

	result.Hosts = hosts

	// 2. 端口扫描
	if len(hosts) > 0 && !s.options.HostDiscoveryOnly {

		// 解析端口列表
		ports, err := utils.ParsePortRange(s.options.Ports)
		if err != nil {
			return result, errors.Wrap(err, "解析端口范围失败")
		}

		// 对每个发现的主机进行端口扫描
		allPorts := s.ScanHostPorts(ctx, hosts, ports)
		result.Ports = allPorts
	}

	if s.options.EnableOSDetect {
		s.annotateOS(ctx, &result)
	}

	result.EndTime = time.Now() // 更新结束时间
	if s.progress != nil {
		s.progress.Debugf("目标 %s 扫描完成，共发现 %d 台主机和 %d 个端口", target, len(result.Hosts), len(result.Ports))
	}
	return result, nil
}

// DiscoverHosts 执行主机发现
func (s *AssetScanner) DiscoverHosts(ctx context.Context, target string) ([]HostInfo, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if s.hostDetector == nil {
		return []HostInfo{}, nil
	}
	var (
		ips []net.IP
		err error
	)
	if ctxAware, ok := s.hostDetector.(ContextAwareHostDetector); ok {
		ips, err = ctxAware.DetectHostsWithContext(ctx, target)
	} else {
		ips, err = s.hostDetector.DetectHosts(target)
	}
	if err != nil {
		return nil, err
	}
	hosts := make([]HostInfo, 0, len(ips))
	for _, ip := range ips {
		if ip == nil {
			continue
		}
		info := HostInfo{
			IP:       ip,
			Status:   "up",
			LastSeen: time.Now(),
		}
		if s.options.ResolveHostname {
			names, err := net.LookupAddr(ip.String())
			if err == nil && len(names) > 0 {
				info.Hostname = strings.TrimSuffix(names[0], ".")
			}
		}
		hosts = append(hosts, info)
	}
	if s.progress != nil {
		s.progress.Debugf("主机发现完成，共 %d 台主机", len(hosts))
	}
	return hosts, nil
}

// ScanHostPorts 对多个主机进行端口扫描
func (s *AssetScanner) ScanHostPorts(ctx context.Context, hosts []HostInfo, ports []int) []PortInfo {
	var allPorts []PortInfo
	var mu sync.Mutex
	var wg sync.WaitGroup

	hostSem := make(chan struct{}, 5)

	if s.progress != nil && len(hosts) > 0 && len(ports) > 0 {
		total := len(hosts) * len(ports)
		desc := fmt.Sprintf("%d 台主机", len(hosts))
		s.progress.StartStage(progress.StagePortScan, total, desc)
		s.progress.Debugf("准备扫描 %d 台主机的 %d 个端口", len(hosts), len(ports))
	}

	var serviceFingerprints []fingerprints.ServiceFingerprint
	if s.options.EnableServiceDetect {
		if fps, err := fingerprints.LoadServiceFingerprints(); err == nil {
			serviceFingerprints = fps
		}
	}

	for _, host := range hosts {
		select {
		case <-ctx.Done():
			return allPorts
		case hostSem <- struct{}{}:
			wg.Add(1)
			go func(h HostInfo) {
				defer wg.Done()
				defer func() { <-hostSem }()

				if ctx.Err() != nil {
					return
				}
				if s.portScanner == nil {
					return
				}
				portResults, err := s.portScanner.ScanPorts(h.IP, ports)
				if err != nil {
					if s.progress != nil && len(ports) > 0 {
						s.progress.Add(progress.StagePortScan, len(ports), fmt.Sprintf("%s 端口扫描失败: %v", h.IP.String(), err))
					}
					return
				}

				s.enrichPortData(h.IP, portResults, serviceFingerprints)
				if s.progress != nil {
					processed := len(portResults)
					for _, pr := range portResults {
						detail := ""
						if s.options.Debug {
							detail = fmt.Sprintf("%s:%d %s", h.IP.String(), pr.Port, pr.State)
						}
						s.progress.Add(progress.StagePortScan, 1, detail)
					}
					if missing := len(ports) - processed; missing > 0 {
						s.progress.Add(progress.StagePortScan, missing, fmt.Sprintf("%s 有 %d 个端口未返回结果", h.IP.String(), missing))
					}
				}

				mu.Lock()
				allPorts = append(allPorts, portResults...)
				mu.Unlock()
			}(host)
		}
	}

	wg.Wait()
	return allPorts
}

// ScanSingleHost 扫描单个主机
func (s *AssetScanner) ScanSingleHost(ctx context.Context, ip string) (HostInfo, []PortInfo, error) {
	// 检查上下文是否已取消
	if ctx.Err() != nil {
		return HostInfo{}, nil, ctx.Err()
	}

	// 验证IP地址
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		// 尝试域名解析
		ips, err := net.LookupIP(ip)
		if err != nil || len(ips) == 0 {
			return HostInfo{}, nil, errors.New("无效的主机地址")
		}
		ip = ips[0].String()
	}

	// 再次检查上下文是否已取消
	if ctx.Err() != nil {
		return HostInfo{}, nil, ctx.Err()
	}

	// 主机发现
	hosts, err := s.DiscoverHosts(ctx, ip)
	if err != nil {
		return HostInfo{}, nil, err
	}

	if len(hosts) == 0 {
		return HostInfo{}, nil, errors.New("主机不可达")
	}

	host := hosts[0]
	var ports []PortInfo
	if s.progress != nil {
		s.progress.Debugf("开始扫描主机 %s", host.IP.String())
	}

	// 端口扫描
	if !s.options.HostDiscoveryOnly && s.portScanner != nil {
		// 再次检查上下文是否已取消
		if ctx.Err() != nil {
			return host, nil, ctx.Err()
		}

		portList, err := utils.ParsePortRange(s.options.Ports)
		if err != nil {
			return host, nil, err
		}

		// 再次检查上下文是否已取消
		if ctx.Err() != nil {
			return host, nil, ctx.Err()
		}

		if s.progress != nil && len(portList) > 0 {
			s.progress.StartStage(progress.StagePortScan, len(portList), fmt.Sprintf("主机 %s", host.IP.String()))
		}

		// 使用正确的ScanPorts方法而不是Scan方法
		ports, err = s.portScanner.ScanPorts(host.IP, portList)
		if err == nil {
			var serviceFingerprints []fingerprints.ServiceFingerprint
			if s.options.EnableServiceDetect {
				serviceFingerprints, _ = fingerprints.LoadServiceFingerprints()
			}
			s.enrichPortData(host.IP, ports, serviceFingerprints)
			if s.progress != nil {
				processed := len(ports)
				for _, pr := range ports {
					detail := ""
					if s.options.Debug {
						detail = fmt.Sprintf("%s:%d %s", host.IP.String(), pr.Port, pr.State)
					}
					s.progress.Add(progress.StagePortScan, 1, detail)
				}
				if missing := len(portList) - processed; missing > 0 {
					s.progress.Add(progress.StagePortScan, missing, fmt.Sprintf("%s 有 %d 个端口未返回结果", host.IP.String(), missing))
				}
			}
		}
		if err != nil {
			return host, nil, err
		}
	}
	if s.progress != nil {
		s.progress.Debugf("主机 %s 端口扫描完成，共记录 %d 个端口", host.IP.String(), len(ports))
	}

	return host, ports, nil
}

func probeServiceBanner(target string, port int, protocol string, timeout time.Duration) ServiceProbeResult {
	useTLS := shouldUseTLS(protocol, port)
	detector := NewServiceDetector(timeout, protocol, useTLS)
	c, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	result, err := detector.Detect(c, target, port)
	if err != nil {
		return ServiceProbeResult{}
	}
	return result
}

func shouldUseTLS(protocol string, port int) bool {
	if strings.ToLower(protocol) == "udp" {
		return false
	}
	switch port {
	case 443, 8443, 9443, 10443:
		return true
	}
	common := strings.ToLower(utils.GetServiceByPort(port))
	if common == "" {
		return false
	}
	return strings.Contains(common, "https") ||
		strings.Contains(common, "ssl") ||
		strings.Contains(common, "tls")
}

func cloneMetadata(src map[string]string) map[string]string {
	if len(src) == 0 {
		return nil
	}
	dst := make(map[string]string, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

func (s *AssetScanner) serviceProbeTimeout() time.Duration {
	timeout := time.Duration(s.options.Timeout) * time.Second
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	return timeout
}

func (s *AssetScanner) enrichPortData(hostIP net.IP, portResults []PortInfo, serviceFingerprints []fingerprints.ServiceFingerprint) {
	if len(portResults) == 0 {
		return
	}

	needProbe := s.options.EnableServiceDetect || s.options.GetBanner
	timeout := s.serviceProbeTimeout()
	host := hostIP.String()

	for i := range portResults {
		if portResults[i].Protocol == "" {
			portResults[i].Protocol = "tcp"
		} else {
			portResults[i].Protocol = strings.ToLower(portResults[i].Protocol)
		}
		if portResults[i].Timestamp.IsZero() {
			portResults[i].Timestamp = time.Now()
		}

		if portResults[i].State != "open" {
			if portResults[i].Service == "" {
				portResults[i].Service = utils.GetServiceByPort(portResults[i].Port)
			}
			continue
		}

		if needProbe {
			probe := probeServiceBanner(host, portResults[i].Port, portResults[i].Protocol, timeout)
			if probe.Banner != "" {
				portResults[i].Banner = probe.Banner
			}
			if len(probe.Raw) > 0 {
				portResults[i].RawBanner = append([]byte(nil), probe.Raw...)
			}
			if probe.TLSCommonName != "" {
				portResults[i].TLSCommonName = probe.TLSCommonName
				portResults[i].TLSIssuer = probe.TLSIssuer
			}
			if len(probe.Metadata) > 0 {
				portResults[i].Metadata = cloneMetadata(probe.Metadata)
			}
		}

		if s.options.EnableServiceDetect && len(serviceFingerprints) > 0 {
			evidence := fingerprints.ServiceEvidence{
				Port:          portResults[i].Port,
				Protocol:      portResults[i].Protocol,
				Banner:        portResults[i].Banner,
				RawBanner:     portResults[i].RawBanner,
				TLSCommonName: portResults[i].TLSCommonName,
				Metadata:      portResults[i].Metadata,
			}
			match := fingerprints.MatchService(serviceFingerprints, evidence)
			if match.Name == "" {
				match.Name = utils.GetServiceByPort(portResults[i].Port)
			}
			portResults[i].Service = match.Name
			portResults[i].Confidence = match.Confidence
		}

		if portResults[i].Service == "" {
			portResults[i].Service = utils.GetServiceByPort(portResults[i].Port)
		}
	}
}

func (s *AssetScanner) annotateOS(ctx context.Context, result *ScanResult) {
	fps, err := fingerprints.LoadOSFingerprints()
	if err != nil || len(fps) == 0 {
		return
	}

	portServices := make(map[string]map[int]string)
	serviceBanners := make(map[string]map[string]string)

	for _, port := range result.Ports {
		ip := port.IP.String()
		if portServices[ip] == nil {
			portServices[ip] = make(map[int]string)
		}
		name := port.Service
		if name == "" {
			name = utils.GetServiceByPort(port.Port)
		}
		if name != "" {
			portServices[ip][port.Port] = name
		}
		if port.Banner != "" {
			if serviceBanners[ip] == nil {
				serviceBanners[ip] = make(map[string]string)
			}
			serviceBanners[ip][strings.ToLower(name)] = port.Banner
		}
	}

	timeout := time.Duration(s.options.Timeout) * time.Second
	if timeout <= 0 {
		timeout = 3 * time.Second
	}

	for i := range result.Hosts {
		ipStr := result.Hosts[i].IP.String()
		ttl, _ := probeTTL(ipStr, timeout)
		ctxData := fingerprints.OSContext{
			TTL:      ttl,
			Services: portServices[ipStr],
			Banners:  serviceBanners[ipStr],
		}
		name, score := fingerprints.MatchOS(fps, ctxData)
		if name != "" {
			result.Hosts[i].OSType = name
			result.Hosts[i].OSConfidence = score
		}
	}
}

var ttlRegex = regexp.MustCompile(`(?i)ttl[=:\s](\d+)`)

func probeTTL(target string, timeout time.Duration) (int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.CommandContext(ctx, "ping", "-n", "1", "-w", fmt.Sprintf("%d", int(timeout.Milliseconds())), target)
	case "darwin":
		cmd = exec.CommandContext(ctx, "ping", "-c", "1", "-t", "1", target)
	default:
		cmd = exec.CommandContext(ctx, "ping", "-c", "1", "-W", fmt.Sprintf("%d", int(timeout.Seconds())), target)
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return 0, err
	}
	matches := ttlRegex.FindStringSubmatch(string(output))
	if len(matches) < 2 {
		return 0, fmt.Errorf("ttl not found")
	}
	val, err := strconv.Atoi(matches[1])
	if err != nil {
		return 0, err
	}
	return val, nil
}

// FastScan 快速扫描（只扫描常用端口）
func (s *AssetScanner) FastScan(ctx context.Context, target string) (ScanResult, error) {
	// 检查上下文是否已取消
	if ctx.Err() != nil {
		return ScanResult{}, ctx.Err()
	}

	// 验证IP地址
	if net.ParseIP(target) == nil {
		// 尝试解析为CIDR
		if _, _, err := net.ParseCIDR(target); err != nil {
			return ScanResult{}, fmt.Errorf("无效的IP地址或CIDR: %s", target)
		}
	}

	// 保存原始端口设置
	originalPorts := s.options.Ports
	defer func() {
		s.options.Ports = originalPorts
	}()

	// 设置快速扫描端口（最常用的10个端口）
	s.options.Ports = "80,443,22,3389,8080,8443,3306,5432,1433,27017"
	s.options.HostDiscoveryOnly = false

	result := ScanResult{
		Target:    target,
		ScanType:  "fast",
		Options:   s.options,
		StartTime: time.Now(),
	}

	// 主机发现
	hosts, err := s.DiscoverHosts(ctx, target)
	if err != nil {
		return result, err
	}

	result.Hosts = hosts

	// 快速端口扫描
	if len(hosts) > 0 {
		portList, _ := utils.ParsePortRange(s.options.Ports)
		allPorts := s.ScanHostPorts(ctx, hosts, portList)
		result.Ports = allPorts
	}

	result.EndTime = time.Now()
	return result, nil
}

// 验证目标是否为有效的CIDR格式
func (s *AssetScanner) isCIDR(target string) bool {
	// 简单的CIDR格式检查，不依赖外部函数
	_, _, err := net.ParseCIDR(target)
	return err == nil
}

// NetworkScan 网络扫描（C类网段快速扫描）
func (s *AssetScanner) NetworkScan(ctx context.Context, network string) (ScanResult, error) {
	// 验证网络格式
	if !s.isCIDR(network) {
		// 尝试将IP转换为C类网段
		ip := net.ParseIP(network)
		if ip != nil {
			// 转换为C类网段 /24
			if ip.To4() != nil {
				network = fmt.Sprintf("%d.%d.%d.0/24", ip[12], ip[13], ip[14])
			}
		} else {
			return ScanResult{}, errors.New("无效的网络地址")
		}
	}

	// 使用快速扫描设置
	return s.FastScan(ctx, network)
}

// CreateScannerFromOptions 根据选项创建合适的扫描器
func CreateScannerFromOptions(options ScanOptions) *AssetScanner {
	if options.Concurrency <= 0 {
		options.Concurrency = 64
	}
	if options.Timeout <= 0 {
		options.Timeout = 3
	}
	parsedPorts, err := utils.ParsePortRange(options.Ports)
	if err != nil || len(parsedPorts) == 0 {
		parsedPorts = utils.GetCommonPorts()[:10]
	}
	timeout := time.Duration(options.Timeout) * time.Second
	hostDetector := NewBasicHostDetector(timeout, parsedPorts)
	rate := options.RateLimit
	if rate < 0 {
		rate = 0
	}
	var portScanner PortScanner
	switch strings.ToLower(options.ScanMethod) {
	case "udp":
		portScanner = NewUDPPortScanner(timeout, options.Concurrency, rate)
	case "syn":
		portScanner = NewSYNPortScanner(timeout, options.Concurrency, rate)
	default:
		portScanner = NewTCPPortScanner(timeout, options.Concurrency, rate)
	}
	return &AssetScanner{
		hostDetector: hostDetector,
		portScanner:  portScanner,
		options:      options,
	}
}

// ValidateScannerOptions 验证扫描器选项
func ValidateScannerOptions(options ScanOptions) error {
	// 验证超时时间
	if options.Timeout < 0 {
		return errors.New("超时时间不能为负数")
	}

	// 验证端口范围
	if options.Ports != "" {
		_, err := utils.ParsePortRange(options.Ports)
		if err != nil {
			return errors.Wrap(err, "无效的端口范围")
		}
	}

	// 验证发现方法
	validMethods := map[string]bool{
		"":      true, // 默认
		"icmp":  true,
		"tcp":   true,
		"arp":   true,
		"mixed": true,
	}

	if !validMethods[options.DiscoveryMethod] {
		return errors.New("不支持的主机发现方法")
	}

	// 验证扫描方法
	validScanMethods := map[string]bool{
		"":    true, // 默认
		"tcp": true,
		"syn": true,
		"udp": true,
	}

	if !validScanMethods[options.ScanMethod] {
		return errors.New("不支持的端口扫描方法")
	}

	// ARP扫描只支持本地网络
	if options.DiscoveryMethod == "arp" && !options.LocalScan {
		return errors.New("ARP扫描仅适用于本地网络扫描")
	}

	return nil
}

// GetScannerStats 获取扫描器统计信息
func GetScannerStats(result ScanResult) map[string]interface{} {
	stats := map[string]interface{}{
		"total_hosts":   len(result.Hosts),
		"total_ports":   len(result.Ports),
		"scan_duration": result.EndTime.Sub(result.StartTime),
		"target":        result.Target,
		"scan_type":     result.ScanType,
	}

	// HostInfo结构体不再包含OSType字段，移除操作系统分布统计

	// 统计服务分布
	serviceDistribution := make(map[string]int)
	for _, port := range result.Ports {
		service := port.Service
		if service == "" {
			service = "unknown"
		}
		serviceDistribution[service]++
	}
	stats["service_distribution"] = serviceDistribution

	// 统计端口状态
	portStatusDistribution := make(map[string]int)
	for _, port := range result.Ports {
		portStatusDistribution[port.State]++
	}
	stats["port_status_distribution"] = portStatusDistribution

	return stats
}
