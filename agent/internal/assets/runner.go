package assets

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/urfave/cli/v2"
	"golang.org/x/net/idna"

	"github.com/m-sec-org/d-eyes/agent/internal/assets/reporters"
	"github.com/m-sec-org/d-eyes/agent/internal/progress"
)

// ScanRequest 描述一次扫描任务
type ScanRequest struct {
	Target   string
	ScanType string
	Options  ScanOptions
}

// AssetsConfig 保存 CLI 层传入的配置
type AssetsConfig struct {
	OutputFormat  string
	OutputFile    string
	Verbose       bool
	ColorOutput   bool
	FastScanPorts string
}

// AssetsRunner 负责 orchestrate 扫描流程与结果输出
type AssetsRunner struct {
	Config         AssetsConfig
	scannerFactory func(ScanOptions) *AssetScanner
	now            func() time.Time
}

// NewAssetsRunner 创建新的运行器实例
func NewAssetsRunner(cfg AssetsConfig) *AssetsRunner {
	return &AssetsRunner{
		Config:         cfg,
		scannerFactory: CreateScannerFromOptions,
		now:            time.Now,
	}
}

// SetScannerFactory 覆盖默认扫描器工厂（用于测试）
func (r *AssetsRunner) SetScannerFactory(factory func(ScanOptions) *AssetScanner) {
	if factory != nil {
		r.scannerFactory = factory
	}
}

// SetNow 覆盖默认时间函数（用于测试）
func (r *AssetsRunner) SetNow(now func() time.Time) {
	if now != nil {
		r.now = now
	}
}

// Execute 执行扫描并输出结果
func (r *AssetsRunner) Execute(ctx context.Context, req ScanRequest) error {
	result, err := r.scanRequest(ctx, req)
	if err != nil {
		return err
	}
	return r.outputResult(result, nil)
}

// ExecuteAggregate 扫描多个请求并聚合输出
func (r *AssetsRunner) ExecuteAggregate(ctx context.Context, requests []ScanRequest, extra map[string]interface{}) error {
	if len(requests) == 0 {
		return errors.New("no scan targets supplied")
	}
	results := make([]ScanResult, 0, len(requests))
	for _, req := range requests {
		res, err := r.scanRequest(ctx, req)
		if err != nil {
			return err
		}
		results = append(results, res)
	}
	merged := mergeScanResults(results)
	return r.outputResult(merged, extra)
}

func (r *AssetsRunner) scanRequest(ctx context.Context, req ScanRequest) (ScanResult, error) {
	if req.Target == "" {
		return ScanResult{}, errors.New("invalid target: empty")
	}
	if r.scannerFactory == nil {
		return ScanResult{}, errors.New("scanner factory not configured")
	}

	scanner := r.scannerFactory(req.Options)
	if scanner == nil {
		return ScanResult{}, errors.New("scanner factory returned nil")
	}

	reporter := progress.NewConsoleReporter(os.Stderr, r.Config.ColorOutput, req.Options.Debug)
	manager := progress.NewManager(reporter, 500*time.Millisecond, req.Options.Debug)
	scanner.SetProgress(manager)
	defer manager.Finish()

	warnPrivilegeRequirement(req.Options, r.Config.Verbose)

	startTime := r.now()

	if isValidIPAddress(req.Target) || isValidDomain(req.Target) {
		host, ports, scanErr := scanner.ScanSingleHost(ctx, req.Target)
		if scanErr != nil {
			return ScanResult{}, fmt.Errorf("scan single host: %w", scanErr)
		}
		return ScanResult{
			Target:    req.Target,
			ScanType:  req.ScanType,
			Options:   req.Options,
			StartTime: startTime,
			EndTime:   r.now(),
			Hosts:     []HostInfo{host},
			Ports:     ports,
		}, nil
	}

	if isValidCIDR(req.Target) {
		result, err := scanner.NetworkScan(ctx, req.Target)
		if err != nil {
			return ScanResult{}, fmt.Errorf("scan network: %w", err)
		}
		if result.Target == "" {
			result.Target = req.Target
		}
		result.ScanType = req.ScanType
		result.Options = req.Options
		if result.StartTime.IsZero() {
			result.StartTime = startTime
		}
		if result.EndTime.IsZero() {
			result.EndTime = r.now()
		}
		return result, nil
	}

	return ScanResult{}, fmt.Errorf("unsupported target: %s", req.Target)
}

func (r *AssetsRunner) outputResult(result ScanResult, extra map[string]interface{}) error {
	format := r.Config.OutputFormat
	if format == "" {
		format = reporters.GetDefaultFormat()
	}

	formatter := reporters.FormatterFactory(format, r.Config.ColorOutput)

	report := reporters.ScanResult{
		Target:     result.Target,
		StartTime:  result.StartTime,
		EndTime:    result.EndTime,
		Hosts:      make([]reporters.HostInfo, 0, len(result.Hosts)),
		Ports:      make([]reporters.PortInfo, 0, len(result.Ports)),
		ScanType:   result.ScanType,
		Options:    map[string]interface{}{},
		Statistics: GetScannerStats(result),
	}

	for k, v := range result.Options.toMap() {
		report.Options[k] = v
	}
	if extra != nil {
		for k, v := range extra {
			report.Statistics[k] = v
		}
	}

	for _, port := range result.Ports {
		report.Ports = append(report.Ports, reporters.PortInfo{
			Port:          port.Port,
			Protocol:      port.Protocol,
			Status:        port.State,
			Service:       port.Service,
			Banner:        port.Banner,
			Confidence:    port.Confidence,
			TLSCommonName: port.TLSCommonName,
			TLSIssuer:     port.TLSIssuer,
			Metadata:      cloneMetadata(port.Metadata),
			Timestamp:     port.Timestamp,
		})
	}

	for _, host := range result.Hosts {
		detected := host.LastSeen
		if detected.IsZero() {
			detected = r.now()
		}
		report.Hosts = append(report.Hosts, reporters.HostInfo{
			IP:           host.IP.String(),
			Hostname:     host.Hostname,
			MACAddress:   host.MACAddress,
			Status:       host.Status,
			OSType:       host.OSType,
			OSConfidence: host.OSConfidence,
			DetectedBy:   "scanner",
			DetectTime:   detected,
		})
	}

	output, err := formatter.FormatScanResult(report)
	if err != nil {
		return fmt.Errorf("format result: %w", err)
	}

	if r.Config.OutputFile != "" {
		if err := os.WriteFile(r.Config.OutputFile, []byte(output), 0644); err != nil {
			return fmt.Errorf("write output file: %w", err)
		}
		fmt.Printf("扫描结果已保存到: %s\n", r.Config.OutputFile)
		return nil
	}

	fmt.Println(output)
	return nil
}

// buildConfigFromCLI 根据 CLI 上下文生成配置
func buildConfigFromCLI(c *cli.Context) AssetsConfig {
	return AssetsConfig{
		OutputFormat:  c.String("format"),
		OutputFile:    c.String("output"),
		Verbose:       c.Bool("verbose"),
		ColorOutput:   c.Bool("color"),
		FastScanPorts: defaultFastScanPorts,
	}
}

// buildScanOptionsFromCLI 构建扫描选项
func buildScanOptionsFromCLI(c *cli.Context) ScanOptions {
	timeout := c.Int("timeout")
	if timeout <= 0 {
		timeout = 2
	}
	return ScanOptions{
		DiscoveryMethod:     c.String("discovery"),
		ScanMethod:          c.String("scan-method"),
		Ports:               c.String("ports"),
		Timeout:             timeout,
		RateLimit:           c.Int("rate"),
		LocalScan:           c.Bool("local"),
		ArpScan:             c.Bool("arp"),
		HostDiscoveryOnly:   c.Bool("hosts-only"),
		ResolveHostname:     c.Bool("resolve"),
		GetBanner:           c.Bool("banner"),
		EnableServiceDetect: c.Bool("service-detect"),
		EnableOSDetect:      c.Bool("os-detect"),
		Interface:           c.String("interface"),
		Verbose:             c.Bool("verbose"),
		Concurrency:         c.Int("concurrency"),
		Debug:               c.Bool("debug"),
	}
}

// isValidDomain 更严格的域名校验，支持单标签内网域
func isValidDomain(domain string) bool {
	if domain == "" || strings.Contains(domain, "/") || strings.ContainsAny(domain, " \t") {
		return false
	}
	if net.ParseIP(domain) != nil {
		return false
	}
	ascii, err := idna.ToASCII(domain)
	if err != nil {
		return false
	}
	if len(ascii) > 253 {
		return false
	}
	parts := strings.Split(ascii, ".")
	for _, part := range parts {
		if part == "" || len(part) > 63 {
			return false
		}
		if !domainLabelRegexp.MatchString(part) {
			return false
		}
	}
	return true
}

var domainLabelRegexp = regexp.MustCompile(`^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$`)

func mergeScanResults(results []ScanResult) ScanResult {
	if len(results) == 0 {
		return ScanResult{}
	}

	hosts := make(map[string]HostInfo)
	ports := make(map[string]PortInfo)
	targets := make(map[string]struct{})
	start := results[0].StartTime
	end := results[0].EndTime
	baseOptions := results[0].Options
	scanType := results[0].ScanType

	for i, res := range results {
		if i == 0 {
			scanType = res.ScanType
		}
		if res.StartTime.Before(start) || start.IsZero() {
			start = res.StartTime
		}
		if res.EndTime.After(end) {
			end = res.EndTime
		}
		targets[res.Target] = struct{}{}

		for _, h := range res.Hosts {
			key := h.IP.String()
			if existing, ok := hosts[key]; ok {
				if h.LastSeen.After(existing.LastSeen) {
					existing.LastSeen = h.LastSeen
				}
				if h.OSType != "" && (existing.OSType == "" || h.OSConfidence >= existing.OSConfidence) {
					existing.OSType = h.OSType
					existing.OSConfidence = h.OSConfidence
				}
				hosts[key] = existing
			} else {
				hosts[key] = h
			}
		}

		for _, p := range res.Ports {
			key := fmt.Sprintf("%s/%s/%d", p.IP.String(), strings.ToLower(p.Protocol), p.Port)
			if existing, ok := ports[key]; ok {
				// 保留状态为 open 的记录
				if existing.State != "open" && p.State == "open" {
					existing = p
				}
				if p.Banner != "" {
					existing.Banner = p.Banner
				}
				if len(p.Metadata) > 0 {
					existing.Metadata = cloneMetadata(p.Metadata)
				}
				if p.Service != "" {
					existing.Service = p.Service
				}
				if existing.Timestamp.Before(p.Timestamp) {
					existing.Timestamp = p.Timestamp
				}
				ports[key] = existing
			} else {
				ports[key] = p
			}
		}
	}

	mergedHosts := make([]HostInfo, 0, len(hosts))
	for _, h := range hosts {
		mergedHosts = append(mergedHosts, h)
	}
	sort.Slice(mergedHosts, func(i, j int) bool {
		return mergedHosts[i].IP.String() < mergedHosts[j].IP.String()
	})

	mergedPorts := make([]PortInfo, 0, len(ports))
	for _, p := range ports {
		mergedPorts = append(mergedPorts, p)
	}
	sort.Slice(mergedPorts, func(i, j int) bool {
		if mergedPorts[i].IP.String() == mergedPorts[j].IP.String() {
			if mergedPorts[i].Port == mergedPorts[j].Port {
				return mergedPorts[i].Protocol < mergedPorts[j].Protocol
			}
			return mergedPorts[i].Port < mergedPorts[j].Port
		}
		return mergedPorts[i].IP.String() < mergedPorts[j].IP.String()
	})

	targetList := make([]string, 0, len(targets))
	for t := range targets {
		targetList = append(targetList, t)
	}
	sort.Strings(targetList)

	return ScanResult{
		Target:    strings.Join(targetList, ","),
		ScanType:  scanType,
		Options:   baseOptions,
		StartTime: start,
		EndTime:   end,
		Hosts:     mergedHosts,
		Ports:     mergedPorts,
	}
}
