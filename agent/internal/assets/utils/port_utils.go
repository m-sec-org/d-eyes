package utils

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// 常用端口映射表
var CommonPortServices = map[int]string{
	20:    "ftp-data",
	21:    "ftp",
	22:    "ssh",
	23:    "telnet",
	25:    "smtp",
	53:    "dns",
	80:    "http",
	110:   "pop3",
	143:   "imap",
	161:   "snmp",
	443:   "https",
	445:   "smb",
	465:   "smtps",
	993:   "imaps",
	995:   "pop3s",
	1433:  "mssql",
	1521:  "oracle",
	2082:  "cpanel",
	2083:  "cpanels",
	2086:  "whm",
	2087:  "whms",
	2222:  "directadmin",
	3306:  "mysql",
	3389:  "rdp",
	5432:  "postgresql",
	5900:  "vnc",
	5901:  "vnc",
	5902:  "vnc",
	8080:  "http-alt",
	8443:  "https-alt",
	8888:  "http-alt",
	9000:  "php-fpm",
	9090:  "webadmin",
	11211: "memcached",
	27017: "mongodb",
	6379:  "redis",
}

// 常用端口列表（优先级排序）
var CommonPorts = []int{
	80, 443, 22, 3389, 8080, 8443, 3306, 5432, 1433, 27017,
	6379, 21, 23, 25, 53, 110, 143, 445, 5900, 5901,
	9000, 9090, 11211, 1521, 465, 993, 995, 2082, 2083, 2086,
	2087, 2222, 8888, 161,
}

// ParsePortRange 解析端口范围字符串
// 支持格式：
// - 单个端口: "80"
// - 逗号分隔: "80,443,8080"
// - 范围表示: "80-100"
// - 混合格式: "80,443,8080-8090"
func ParsePortRange(portRange string) ([]int, error) {
	var ports []int
	portMap := make(map[int]bool)

	if portRange == "" {
		// 返回常用端口列表
		return CommonPorts, nil
	}

	// 分割多个范围
	ranges := strings.Split(portRange, ",")

	for _, r := range ranges {
		r = strings.TrimSpace(r)
		if r == "" {
			continue
		}

		// 检查是否为范围
		if strings.Contains(r, "-") {
			parts := strings.Split(r, "-")
			if len(parts) != 2 {
				return nil, fmt.Errorf("无效的端口范围格式: %s", r)
			}

			start, err := strconv.Atoi(strings.TrimSpace(parts[0]))
			if err != nil {
				return nil, fmt.Errorf("无效的起始端口: %s", parts[0])
			}

			end, err := strconv.Atoi(strings.TrimSpace(parts[1]))
			if err != nil {
				return nil, fmt.Errorf("无效的结束端口: %s", parts[1])
			}

			// 验证端口范围
			if !IsValidPortRange(start, end) {
				return nil, fmt.Errorf("无效的端口范围: %d-%d", start, end)
			}

			// 添加范围内的所有端口
			for port := start; port <= end; port++ {
				if !portMap[port] {
					portMap[port] = true
					ports = append(ports, port)
				}
			}
		} else {
			// 单个端口
			port, err := strconv.Atoi(r)
			if err != nil {
				return nil, fmt.Errorf("无效的端口号: %s", r)
			}

			if !IsValidPort(port) {
				return nil, fmt.Errorf("无效的端口号: %d", port)
			}

			if !portMap[port] {
				portMap[port] = true
				ports = append(ports, port)
			}
		}
	}

	// 按端口号排序
	sort.Ints(ports)

	return ports, nil
}

// IsValidPort 验证端口号是否有效
func IsValidPort(port int) bool {
	return port > 0 && port <= 65535
}

// IsValidPortRange 验证端口范围是否有效
func IsValidPortRange(start, end int) bool {
	return IsValidPort(start) && IsValidPort(end) && start <= end
}

// GetServiceByPort 根据端口号获取常用服务名称
func GetServiceByPort(port int) string {
	if service, exists := CommonPortServices[port]; exists {
		return service
	}
	return "unknown"
}

// GetCommonPorts 获取常用端口列表
func GetCommonPorts() []int {
	// 返回副本以避免修改原数组
	commonPortsCopy := make([]int, len(CommonPorts))
	copy(commonPortsCopy, CommonPorts)
	return commonPortsCopy
}

// GetWellKnownPorts 获取知名端口（0-1023）
func GetWellKnownPorts() []int {
	var ports []int
	for port := 1; port <= 1023; port++ {
		ports = append(ports, port)
	}
	return ports
}

// GetRegisteredPorts 获取注册端口（1024-49151）
func GetRegisteredPorts() []int {
	var ports []int
	for port := 1024; port <= 49151; port++ {
		ports = append(ports, port)
	}
	return ports
}

// GetDynamicPorts 获取动态/私有端口（49152-65535）
func GetDynamicPorts() []int {
	var ports []int
	for port := 49152; port <= 65535; port++ {
		ports = append(ports, port)
	}
	return ports
}

// IsWellKnownPort 判断是否为知名端口
func IsWellKnownPort(port int) bool {
	return port >= 1 && port <= 1023
}

// IsRegisteredPort 判断是否为注册端口
func IsRegisteredPort(port int) bool {
	return port >= 1024 && port <= 49151
}

// IsDynamicPort 判断是否为动态/私有端口
func IsDynamicPort(port int) bool {
	return port >= 49152 && port <= 65535
}

// GetPortType 获取端口类型
func GetPortType(port int) string {
	if !IsValidPort(port) {
		return "invalid"
	}

	if IsWellKnownPort(port) {
		return "well-known"
	} else if IsRegisteredPort(port) {
		return "registered"
	} else if IsDynamicPort(port) {
		return "dynamic"
	}

	return "unknown"
}

// ExpandPortList 扩展端口列表，支持特殊标记
func ExpandPortList(portSpec string) ([]int, error) {
	// 特殊标记处理
	switch strings.ToLower(portSpec) {
	case "", "common":
		return GetCommonPorts(), nil
	case "well-known":
		return GetWellKnownPorts(), nil
	case "registered":
		return GetRegisteredPorts(), nil
	case "all":
		// 所有端口太多，返回常用端口集
		return GetCommonPorts(), nil
	default:
		// 正常解析端口范围
		return ParsePortRange(portSpec)
	}
}

// PortsToString 将端口列表转换为字符串表示
func PortsToString(ports []int) string {
	if len(ports) == 0 {
		return ""
	}

	// 按端口排序
	sort.Ints(ports)

	var result strings.Builder
	start := ports[0]
	prev := start

	for i := 1; i < len(ports); i++ {
		if ports[i] != prev+1 {
			// 端口不连续，输出范围或单个端口
			if start == prev {
				result.WriteString(fmt.Sprintf("%d,", start))
			} else {
				result.WriteString(fmt.Sprintf("%d-%d,", start, prev))
			}
			start = ports[i]
		}
		prev = ports[i]
	}

	// 处理最后一个范围
	if start == prev {
		result.WriteString(fmt.Sprintf("%d", start))
	} else {
		result.WriteString(fmt.Sprintf("%d-%d", start, prev))
	}

	return result.String()
}

// FilterCommonPorts 过滤常用端口
func FilterCommonPorts(ports []int) []int {
	var result []int
	commonPortMap := make(map[int]bool)

	// 创建常用端口的映射
	for _, port := range CommonPorts {
		commonPortMap[port] = true
	}

	// 过滤出常用端口
	for _, port := range ports {
		if commonPortMap[port] {
			result = append(result, port)
		}
	}

	return result
}

// IsCommonPort 判断是否为常用端口
func IsCommonPort(port int) bool {
	_, exists := CommonPortServices[port]
	return exists
}

// GetPortsByService 根据服务名称获取端口号
func GetPortsByService(service string) []int {
	var ports []int
	service = strings.ToLower(service)

	for port, s := range CommonPortServices {
		if strings.ToLower(s) == service {
			ports = append(ports, port)
		}
	}

	return ports
}
