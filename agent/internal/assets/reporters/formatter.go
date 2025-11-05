package reporters

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/olekukonko/tablewriter"
)

// HostInfo 主机信息结构
type HostInfo struct {
	IP           string    `json:"ip"`
	Hostname     string    `json:"hostname"`
	MACAddress   string    `json:"mac_address,omitempty"`
	Status       string    `json:"status"`
	OSType       string    `json:"os_type,omitempty"`
	OSConfidence float64   `json:"os_confidence,omitempty"`
	DetectedBy   string    `json:"detected_by"`
	DetectTime   time.Time `json:"detect_time"`
}

// PortInfo 端口信息结构
type PortInfo struct {
	Port          int               `json:"port"`
	Protocol      string            `json:"protocol"`
	Status        string            `json:"status"`
	Service       string            `json:"service,omitempty"`
	Banner        string            `json:"banner,omitempty"`
	Confidence    float64           `json:"confidence,omitempty"`
	TLSCommonName string            `json:"tls_cn,omitempty"`
	TLSIssuer     string            `json:"tls_issuer,omitempty"`
	Metadata      map[string]string `json:"metadata,omitempty"`
	Timestamp     time.Time         `json:"timestamp"`
}

// ScanResult 扫描结果结构体
type ScanResult struct {
	Target     string                 `json:"target"`
	StartTime  time.Time              `json:"start_time"`
	EndTime    time.Time              `json:"end_time"`
	Hosts      []HostInfo             `json:"hosts,omitempty"`
	Ports      []PortInfo             `json:"ports,omitempty"`
	ScanType   string                 `json:"scan_type"`
	Options    map[string]interface{} `json:"options"`
	Statistics map[string]interface{} `json:"statistics"`
}

// Formatter 扫描结果格式化接口
type Formatter interface {
	FormatHosts(hosts []HostInfo) (string, error)
	FormatPorts(ports []PortInfo) (string, error)
	FormatScanResult(result ScanResult) (string, error)
}

// JSONFormatter JSON格式输出
type JSONFormatter struct{}

// NewJSONFormatter 创建JSON格式化器
func NewJSONFormatter() *JSONFormatter {
	return &JSONFormatter{}
}

// FormatHosts 格式化主机列表
func (f *JSONFormatter) FormatHosts(hosts []HostInfo) (string, error) {
	output, err := json.MarshalIndent(hosts, "", "  ")
	if err != nil {
		return "", err
	}
	return string(output), nil
}

// FormatPorts 格式化端口列表
func (f *JSONFormatter) FormatPorts(ports []PortInfo) (string, error) {
	output, err := json.MarshalIndent(ports, "", "  ")
	if err != nil {
		return "", err
	}
	return string(output), nil
}

// FormatScanResult 格式化扫描结果
func (f *JSONFormatter) FormatScanResult(result ScanResult) (string, error) {
	output, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return "", err
	}
	return string(output), nil
}

// TableFormatter 表格格式输出
type TableFormatter struct {
	Color bool
}

// NewTableFormatter 创建表格格式化器
func NewTableFormatter(color bool) *TableFormatter {
	return &TableFormatter{
		Color: color,
	}
}

// FormatHosts 格式化主机列表
func (f *TableFormatter) FormatHosts(hosts []HostInfo) (string, error) {
	if len(hosts) == 0 {
		return "未发现活跃主机", nil
	}

	// 按IP地址排序
	sort.Slice(hosts, func(i, j int) bool {
		return hosts[i].IP < hosts[j].IP
	})

	var b strings.Builder
	table := tablewriter.NewWriter(&b)
	table.SetHeader([]string{"IP地址", "主机名", "MAC地址", "状态", "操作系统", "置信度", "检测方法", "检测时间"})
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.SetAutoWrapText(false)

	if f.Color {
		table.SetHeaderColor(
			tablewriter.Colors{tablewriter.FgCyanColor, tablewriter.Bold},
			tablewriter.Colors{tablewriter.FgCyanColor, tablewriter.Bold},
			tablewriter.Colors{tablewriter.FgCyanColor, tablewriter.Bold},
			tablewriter.Colors{tablewriter.FgCyanColor, tablewriter.Bold},
			tablewriter.Colors{tablewriter.FgCyanColor, tablewriter.Bold},
			tablewriter.Colors{tablewriter.FgCyanColor, tablewriter.Bold},
			tablewriter.Colors{tablewriter.FgCyanColor, tablewriter.Bold},
			tablewriter.Colors{tablewriter.FgCyanColor, tablewriter.Bold},
		)
	}

	for _, host := range hosts {
		confidence := ""
		if host.OSConfidence > 0 {
			confidence = fmt.Sprintf("%.1f", host.OSConfidence)
		}
		row := []string{
			host.IP,
			host.Hostname,
			host.MACAddress,
			host.Status,
			host.OSType,
			confidence,
			host.DetectedBy,
			host.DetectTime.Format("2006-01-02 15:04:05"),
		}
		table.Append(row)
	}

	table.Render()
	return b.String(), nil
}

// FormatPorts 格式化端口列表
func (f *TableFormatter) FormatPorts(ports []PortInfo) (string, error) {
	if len(ports) == 0 {
		return "未发现开放端口", nil
	}

	// 按端口号排序
	sort.Slice(ports, func(i, j int) bool {
		return ports[i].Port < ports[j].Port
	})

	var b strings.Builder
	table := tablewriter.NewWriter(&b)
	table.SetHeader([]string{"端口", "协议", "状态", "服务", "置信度", "Banner信息", "扫描时间"})
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.SetAutoWrapText(false)

	if f.Color {
		table.SetHeaderColor(
			tablewriter.Colors{tablewriter.FgCyanColor, tablewriter.Bold},
			tablewriter.Colors{tablewriter.FgCyanColor, tablewriter.Bold},
			tablewriter.Colors{tablewriter.FgCyanColor, tablewriter.Bold},
			tablewriter.Colors{tablewriter.FgCyanColor, tablewriter.Bold},
			tablewriter.Colors{tablewriter.FgCyanColor, tablewriter.Bold},
			tablewriter.Colors{tablewriter.FgCyanColor, tablewriter.Bold},
			tablewriter.Colors{tablewriter.FgCyanColor, tablewriter.Bold},
		)
	}

	for _, port := range ports {
		confidence := ""
		if port.Confidence > 0 {
			confidence = fmt.Sprintf("%.1f", port.Confidence)
		}
		bannerInfo := port.Banner
		if server := port.Metadata["http.server"]; server != "" {
			if bannerInfo != "" {
				bannerInfo += " "
			}
			bannerInfo += fmt.Sprintf("[Server: %s]", server)
		}
		if port.TLSCommonName != "" {
			if bannerInfo != "" {
				bannerInfo += " "
			}
			bannerInfo += fmt.Sprintf("[TLS CN: %s]", port.TLSCommonName)
		}
		row := []string{
			fmt.Sprintf("%d", port.Port),
			port.Protocol,
			port.Status,
			port.Service,
			confidence,
			bannerInfo,
			port.Timestamp.Format("2006-01-02 15:04:05"),
		}
		table.Append(row)
	}

	table.Render()
	return b.String(), nil
}

// FormatScanResult 格式化扫描结果
func (f *TableFormatter) FormatScanResult(result ScanResult) (string, error) {
	var b strings.Builder

	// 输出扫描摘要
	b.WriteString("\n===== 扫描结果摘要 =====\n")
	b.WriteString(fmt.Sprintf("扫描目标: %s\n", result.Target))
	b.WriteString(fmt.Sprintf("扫描开始时间: %s\n", result.StartTime.Format("2006-01-02 15:04:05")))
	b.WriteString(fmt.Sprintf("扫描结束时间: %s\n", result.EndTime.Format("2006-01-02 15:04:05")))
	b.WriteString(fmt.Sprintf("扫描耗时: %v\n", result.EndTime.Sub(result.StartTime)))
	b.WriteString(fmt.Sprintf("发现主机数: %d\n", len(result.Hosts)))
	b.WriteString(fmt.Sprintf("发现开放端口数: %d\n", len(result.Ports)))

	// 输出主机列表
	if len(result.Hosts) > 0 {
		b.WriteString("\n===== 主机列表 =====\n")
		hostOutput, err := f.FormatHosts(result.Hosts)
		if err != nil {
			return "", err
		}
		b.WriteString(hostOutput)
	}

	// 输出端口列表
	if len(result.Ports) > 0 {
		b.WriteString("\n===== 端口列表 =====\n")
		portOutput, err := f.FormatPorts(result.Ports)
		if err != nil {
			return "", err
		}
		b.WriteString(portOutput)
	}

	return b.String(), nil
}

// PlainTextFormatter 纯文本格式输出
type PlainTextFormatter struct{}

// NewPlainTextFormatter 创建纯文本格式化器
func NewPlainTextFormatter() *PlainTextFormatter {
	return &PlainTextFormatter{}
}

// FormatHosts 格式化主机列表
func (f *PlainTextFormatter) FormatHosts(hosts []HostInfo) (string, error) {
	if len(hosts) == 0 {
		return "未发现活跃主机", nil
	}

	// 按IP地址排序
	sort.Slice(hosts, func(i, j int) bool {
		return hosts[i].IP < hosts[j].IP
	})

	var b strings.Builder
	b.WriteString("\n活跃主机列表:\n")
	b.WriteString(strings.Repeat("-", 80) + "\n")

	for _, host := range hosts {
		b.WriteString(fmt.Sprintf("IP: %-15s 主机名: %-20s MAC: %s\n", host.IP, host.Hostname, host.MACAddress))
		b.WriteString(fmt.Sprintf("  状态: %s  OS: %s  检测方法: %s\n", host.Status, host.OSType, host.DetectedBy))
		b.WriteString(fmt.Sprintf("  检测时间: %s\n", host.DetectTime.Format("2006-01-02 15:04:05")))
		b.WriteString(strings.Repeat("-", 80) + "\n")
	}

	return b.String(), nil
}

// FormatPorts 格式化端口列表
func (f *PlainTextFormatter) FormatPorts(ports []PortInfo) (string, error) {
	if len(ports) == 0 {
		return "未发现开放端口", nil
	}

	// 按端口号排序
	sort.Slice(ports, func(i, j int) bool {
		return ports[i].Port < ports[j].Port
	})

	var b strings.Builder
	b.WriteString("\n开放端口列表:\n")
	b.WriteString(strings.Repeat("-", 80) + "\n")

	for _, port := range ports {
		b.WriteString(fmt.Sprintf("%d/%s  %-15s  %s\n", port.Port, port.Protocol, port.Service, port.Status))
		if port.Confidence > 0 {
			b.WriteString(fmt.Sprintf("  置信度: %.1f\n", port.Confidence))
		}
		if port.Banner != "" {
			b.WriteString(fmt.Sprintf("  Banner: %s\n", port.Banner))
		}
		if port.TLSCommonName != "" {
			if port.TLSIssuer != "" {
				b.WriteString(fmt.Sprintf("  TLS: CN=%s, Issuer=%s\n", port.TLSCommonName, port.TLSIssuer))
			} else {
				b.WriteString(fmt.Sprintf("  TLS: CN=%s\n", port.TLSCommonName))
			}
		}
		if server := port.Metadata["http.server"]; server != "" {
			b.WriteString(fmt.Sprintf("  HTTP Server: %s\n", server))
		}
		b.WriteString(fmt.Sprintf("  扫描时间: %s\n", port.Timestamp.Format("2006-01-02 15:04:05")))
		b.WriteString(strings.Repeat("-", 80) + "\n")
	}

	return b.String(), nil
}

// FormatScanResult 格式化扫描结果
func (f *PlainTextFormatter) FormatScanResult(result ScanResult) (string, error) {
	var b strings.Builder

	// 输出扫描摘要
	b.WriteString(strings.Repeat("=", 50) + "\n")
	b.WriteString("          资产扫描结果报告          \n")
	b.WriteString(strings.Repeat("=", 50) + "\n\n")

	b.WriteString(fmt.Sprintf("扫描目标: %s\n", result.Target))
	b.WriteString(fmt.Sprintf("扫描类型: %s\n", result.ScanType))
	b.WriteString(fmt.Sprintf("扫描选项: %v\n", result.Options))
	b.WriteString(fmt.Sprintf("扫描开始时间: %s\n", result.StartTime.Format("2006-01-02 15:04:05")))
	b.WriteString(fmt.Sprintf("扫描结束时间: %s\n", result.EndTime.Format("2006-01-02 15:04:05")))
	b.WriteString(fmt.Sprintf("扫描耗时: %v\n\n", result.EndTime.Sub(result.StartTime)))

	b.WriteString(fmt.Sprintf("发现主机数: %d\n", len(result.Hosts)))
	b.WriteString(fmt.Sprintf("发现开放端口数: %d\n\n", len(result.Ports)))

	// 输出主机列表
	if len(result.Hosts) > 0 {
		hostOutput, err := f.FormatHosts(result.Hosts)
		if err != nil {
			return "", err
		}
		b.WriteString(hostOutput)
	}

	// 输出端口列表
	if len(result.Ports) > 0 {
		portOutput, err := f.FormatPorts(result.Ports)
		if err != nil {
			return "", err
		}
		b.WriteString(portOutput)
	}

	// 输出统计信息
	if len(result.Statistics) > 0 {
		b.WriteString("\n===== 扫描统计 =====\n")
		for k, v := range result.Statistics {
			b.WriteString(fmt.Sprintf("%s: %v\n", k, v))
		}
	}

	return b.String(), nil
}

// CSVFormatter CSV格式输出
type CSVFormatter struct{}

// NewCSVFormatter 创建CSV格式化器
func NewCSVFormatter() *CSVFormatter {
	return &CSVFormatter{}
}

// FormatHosts 格式化主机列表
func (f *CSVFormatter) FormatHosts(hosts []HostInfo) (string, error) {
	if len(hosts) == 0 {
		return "IP地址,主机名,MAC地址,状态,操作系统,检测方法,检测时间", nil
	}

	var b strings.Builder
	// 输出CSV表头
	b.WriteString("IP地址,主机名,MAC地址,状态,操作系统,检测方法,检测时间\n")

	for _, host := range hosts {
		// 转义CSV字段中的逗号和引号
		hostname := escapeCSV(host.Hostname)
		mac := escapeCSV(host.MACAddress)
		osType := escapeCSV(host.OSType)
		detectedBy := escapeCSV(host.DetectedBy)

		b.WriteString(fmt.Sprintf("%s,%s,%s,%s,%s,%s,%s\n",
			host.IP, hostname, mac, host.Status, osType, detectedBy,
			host.DetectTime.Format("2006-01-02 15:04:05"),
		))
	}

	return b.String(), nil
}

// FormatPorts 格式化端口列表
func (f *CSVFormatter) FormatPorts(ports []PortInfo) (string, error) {
	if len(ports) == 0 {
		return "端口,协议,状态,服务,置信度,Banner信息,扫描时间", nil
	}

	var b strings.Builder
	// 输出CSV表头
	b.WriteString("端口,协议,状态,服务,置信度,Banner信息,扫描时间\n")

	for _, port := range ports {
		// 转义CSV字段中的逗号和引号
		service := escapeCSV(port.Service)
		confidence := ""
		if port.Confidence > 0 {
			confidence = fmt.Sprintf("%.1f", port.Confidence)
		}
		confidence = escapeCSV(confidence)

		bannerInfo := port.Banner
		if server := port.Metadata["http.server"]; server != "" {
			if bannerInfo != "" {
				bannerInfo += " "
			}
			bannerInfo += fmt.Sprintf("[Server: %s]", server)
		}
		if port.TLSCommonName != "" {
			if bannerInfo != "" {
				bannerInfo += " "
			}
			bannerInfo += fmt.Sprintf("[TLS CN: %s]", port.TLSCommonName)
		}
		banner := escapeCSV(bannerInfo)

		b.WriteString(fmt.Sprintf("%d,%s,%s,%s,%s,%s,%s\n",
			port.Port, port.Protocol, port.Status, service, confidence, banner,
			port.Timestamp.Format("2006-01-02 15:04:05"),
		))
	}

	return b.String(), nil
}

// FormatScanResult 格式化扫描结果
func (f *CSVFormatter) FormatScanResult(result ScanResult) (string, error) {
	// CSV格式只输出主机和端口的详细信息
	var b strings.Builder

	b.WriteString("===== 主机列表 =====\n")
	hosts, err := f.FormatHosts(result.Hosts)
	if err != nil {
		return "", err
	}
	b.WriteString(hosts)

	b.WriteString("\n\n===== 端口列表 =====\n")
	ports, err := f.FormatPorts(result.Ports)
	if err != nil {
		return "", err
	}
	b.WriteString(ports)

	return b.String(), nil
}

// escapeCSV 转义CSV字段
func escapeCSV(s string) string {
	if strings.Contains(s, ",") || strings.Contains(s, "\n") || strings.Contains(s, "\r") || strings.Contains(s, "\"") {
		// 替换双引号为两个双引号
		s = strings.ReplaceAll(s, "\"", "\"\"")
		// 用双引号包裹整个字段
		s = "\"" + s + "\""
	}
	return s
}

// FormatterFactory 根据格式类型创建格式化器
func FormatterFactory(formatType string, color bool) Formatter {
	switch strings.ToLower(formatType) {
	case "json":
		return NewJSONFormatter()
	case "csv":
		return NewCSVFormatter()
	case "table":
		return NewTableFormatter(color)
	default:
		return NewPlainTextFormatter()
	}
}

// GetSupportedFormats 获取支持的输出格式列表
func GetSupportedFormats() []string {
	return []string{"text", "table", "json", "csv"}
}

// ValidateFormat 验证输出格式是否支持
func ValidateFormat(format string) bool {
	supportedFormats := GetSupportedFormats()
	for _, f := range supportedFormats {
		if strings.ToLower(format) == f {
			return true
		}
	}
	return false
}

// GetDefaultFormat 获取默认输出格式
func GetDefaultFormat() string {
	return "table"
}
