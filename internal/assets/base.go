package assets

import (
	"context"
	"net"
	"time"
)

// ScanOptions 扫描选项
type ScanOptions struct {
	DiscoveryMethod     string
	ScanMethod          string
	Ports               string
	Timeout             int
	Concurrency         int
	RateLimit           int
	LocalScan           bool
	ArpScan             bool
	HostDiscoveryOnly   bool
	ResolveHostname     bool
	GetBanner           bool
	EnableServiceDetect bool
	EnableOSDetect      bool
	Interface           string
	Verbose             bool
	Debug               bool
}

func (o ScanOptions) toMap() map[string]interface{} {
	return map[string]interface{}{
		"discovery":      o.DiscoveryMethod,
		"scan_method":    o.ScanMethod,
		"ports":          o.Ports,
		"timeout":        o.Timeout,
		"rate_limit":     o.RateLimit,
		"local_scan":     o.LocalScan,
		"arp_scan":       o.ArpScan,
		"hosts_only":     o.HostDiscoveryOnly,
		"resolve":        o.ResolveHostname,
		"banner":         o.GetBanner,
		"service_detect": o.EnableServiceDetect,
		"os_detect":      o.EnableOSDetect,
		"interface":      o.Interface,
		"verbose":        o.Verbose,
		"debug":          o.Debug,
		"concurrency":    o.Concurrency,
	}
}

// HostInfo 主机信息
type HostInfo struct {
	IP           net.IP    // 主机IP地址
	Hostname     string    // 主机名
	MACAddress   string    // MAC地址（内网）
	Status       string    // 状态 (up, down)
	LastSeen     time.Time // 最后发现时间
	OSType       string    // 推测的操作系统
	OSConfidence float64   // 置信度
}

// PortInfo 端口信息
type PortInfo struct {
	IP            net.IP            // 主机IP地址
	Port          int               // 端口号
	State         string            // 状态 (open, closed, filtered)
	Service       string            // 服务名称
	Banner        string            // 服务Banner（文本形式）
	RawBanner     []byte            // 原始Banner字节序列（用于二进制匹配）
	Confidence    float64           // 服务识别置信度
	Protocol      string            // 协议 (tcp/udp)
	TLSCommonName string            // 服务端TLS证书CN
	TLSIssuer     string            // 服务端TLS证书颁发者
	Metadata      map[string]string // 额外识别信息（如协议特征、响应摘要）
	Timestamp     time.Time         // 识别时间
}

// ScanResult 扫描结果
type ScanResult struct {
	Target    string      // 扫描目标
	ScanType  string      // 扫描类型
	Options   ScanOptions // 扫描选项
	StartTime time.Time   // 开始时间
	EndTime   time.Time   // 结束时间
	Hosts     []HostInfo  // 发现的主机列表
	Ports     []PortInfo  // 发现的端口列表
}

// Scanner 扫描器接口
type Scanner interface {
	// Init 初始化扫描器
	Init(options *ScanOptions)
	// Scan 执行扫描
	Scan() ([]HostInfo, error)
	// Stop 停止扫描
	Stop()
	// GetProgress 获取扫描进度
	GetProgress() float64
}

// HostDetector 主机探测器接口
type HostDetector interface {
	// DetectHosts 探测主机存活
	DetectHosts(target string) ([]net.IP, error)
	// 为了简化实现，暂时移除其他方法要求
}

// ContextAwareHostDetector 支持上下文取消的主机探测器
type ContextAwareHostDetector interface {
	DetectHostsWithContext(ctx context.Context, target string) ([]net.IP, error)
}

// PortScanner 端口扫描器接口
type PortScanner interface {
	// ScanPorts 扫描目标主机的端口
	ScanPorts(ip net.IP, ports []int) ([]PortInfo, error)
	// ScanPort 扫描单个端口
	ScanPort(ip net.IP, port int) (PortInfo, error)
	// ParsePortRange 解析端口范围字符串
	ParsePortRange(portRange string) ([]int, error)
}

// OSDetector 操作系统识别器接口
type OSDetector interface {
	// DetectOS 识别目标主机的操作系统
	DetectOS(ip net.IP) (string, error)
	// GetTtlRange 获取TTL范围对应的操作系统信息
	GetTtlRange(ttl int) string
}

// NetworkDiscoverer 网络发现器接口
type NetworkDiscoverer interface {
	// GetLocalNetworks 获取本地网络列表
	GetLocalNetworks() ([]string, error)
	// GetDefaultGateway 获取默认网关
	GetDefaultGateway() (net.IP, error)
	// DiscoverNeighbors 发现邻居主机
	DiscoverNeighbors(network string) ([]net.IP, error)
}

// Reporter 报告生成器接口
type Reporter interface {
	// Generate 生成报告
	Generate(hosts []HostInfo) ([]byte, error)
	// Save 保存报告到文件
	Save(hosts []HostInfo, filePath string) error
}

// ScannerFactory 扫描器工厂接口
type ScannerFactory interface {
	// CreateScanner 创建扫描器实例
	CreateScanner() Scanner
}

// ReporterFactory 报告生成器工厂接口
type ReporterFactory interface {
	// CreateReporter 创建报告生成器实例
	CreateReporter(format string) Reporter
}
