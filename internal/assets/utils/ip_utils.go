package utils

import (
	"fmt"
	"net"
	"strings"
)

// ParseCIDR 解析CIDR网段，返回IP地址和子网掩码
func ParseCIDR(cidr string) (net.IP, *net.IPNet, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, nil, fmt.Errorf("解析CIDR失败: %w", err)
	}
	return ip, ipnet, nil
}

// GenerateIPRange 生成IP地址范围
func GenerateIPRange(network *net.IPNet) []net.IP {
	var ips []net.IP

	// 确保是IPv4地址
	baseIP := network.IP.To4()
	if baseIP == nil {
		return ips
	}

	// 计算广播地址
	broadcast := make(net.IP, len(baseIP))
	for i := range baseIP {
		broadcast[i] = baseIP[i] | ^network.Mask[i]
	}

	current := make(net.IP, len(baseIP))
	copy(current, baseIP)

	for {
		ipCopy := make(net.IP, len(current))
		copy(ipCopy, current)
		ips = append(ips, ipCopy)

		if current.Equal(broadcast) {
			break
		}
		incrementIPInPlace(current)
	}
	return ips
}

// incrementIP 递增IP地址
func incrementIP(ip net.IP) net.IP {
	ip = ip.To4()
	newIP := make(net.IP, len(ip))
	copy(newIP, ip)
	incrementIPInPlace(newIP)
	return newIP
}

// incrementIPInPlace 在原地递增IP地址
func incrementIPInPlace(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] > 0 {
			break
		}
	}
}

// IsPrivateIP 判断是否为私有IP地址
func IsPrivateIP(ip net.IP) bool {
	if ip.To4() == nil {
		return false
	}

	// RFC 1918私有地址范围
	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
	}

	for _, cidr := range privateRanges {
		_, ipnet, _ := net.ParseCIDR(cidr)
		if ipnet.Contains(ip) {
			return true
		}
	}

	// 127.0.0.0/8 本地回环地址
	_, loopback, _ := net.ParseCIDR("127.0.0.0/8")
	if loopback.Contains(ip) {
		return true
	}

	return false
}

// IsLoopbackIP 判断是否为回环IP地址
func IsLoopbackIP(ip net.IP) bool {
	return ip.IsLoopback()
}

// IsIPv4 判断是否为IPv4地址
func IsIPv4(ip net.IP) bool {
	return ip.To4() != nil
}

// IsIPv6 判断是否为IPv6地址
func IsIPv6(ip net.IP) bool {
	return ip.To4() == nil && ip.To16() != nil
}

// GetIPFromTarget 从目标字符串获取IP地址
func GetIPFromTarget(target string) (net.IP, error) {
	// 尝试直接解析为IP
	ip := net.ParseIP(target)
	if ip != nil {
		return ip, nil
	}

	// 尝试进行DNS解析
	addrs, err := net.LookupIP(target)
	if err != nil {
		return nil, fmt.Errorf("解析目标失败: %v", err)
	}

	// 优先返回IPv4地址
	for _, addr := range addrs {
		if addr.To4() != nil {
			return addr, nil
		}
	}

	// 如果没有IPv4地址，返回第一个IPv6地址
	if len(addrs) > 0 {
		return addrs[0], nil
	}

	return nil, fmt.Errorf("无法解析目标为IP地址")
}

// GetIPsFromTarget 从目标字符串获取所有IP地址
func GetIPsFromTarget(target string) ([]net.IP, error) {
	// 检查是否为CIDR格式
	if strings.Contains(target, "/") {
		_, ipnet, err := ParseCIDR(target)
		if err != nil {
			return nil, err
		}
		return GenerateIPRange(ipnet), nil
	}

	// 尝试直接解析为IP
	ip := net.ParseIP(target)
	if ip != nil {
		return []net.IP{ip}, nil
	}

	// 尝试进行DNS解析
	addrs, err := net.LookupIP(target)
	if err != nil {
		return nil, fmt.Errorf("解析目标失败: %v", err)
	}

	return addrs, nil
}

// GetSubnetMask 获取子网掩码对应的CIDR值
func GetSubnetMask(mask net.IPMask) int {
	ones, _ := mask.Size()
	return ones
}

// GetNetworkAddress 获取IP地址的网络地址
func GetNetworkAddress(ip net.IP, mask net.IPMask) net.IP {
	return ip.Mask(mask)
}

// GetNetworkFromIP 根据IP地址和子网掩码获取网络地址
func GetNetworkFromIP(ip string, mask int) (string, error) {
	ipAddr := net.ParseIP(ip)
	if ipAddr == nil {
		return "", fmt.Errorf("无效的IP地址: %s", ip)
	}

	cidrMask := net.CIDRMask(mask, 32)
	networkAddr := ipAddr.Mask(cidrMask)
	return fmt.Sprintf("%s/%d", networkAddr.String(), mask), nil
}

// ConvertToNetwork 将IP地址或CIDR转换为指定掩码的网络地址
func ConvertToNetwork(target string, maskBits int) string {
	// 尝试解析为CIDR
	if strings.Contains(target, "/") {
		ip, _, err := ParseCIDR(target)
		if err != nil {
			return target
		}
		// 创建新的掩码
		newMask := net.CIDRMask(maskBits, 32)
		newIP := net.IP(make([]byte, 4))
		for i := 0; i < 4; i++ {
			newIP[i] = ip[i] & newMask[i]
		}
		return fmt.Sprintf("%s/%d", newIP.String(), maskBits)
	}

	// 尝试解析为IP地址
	ip := net.ParseIP(target)
	if ip != nil {
		ip = ip.To4()
		if ip != nil {
			// 创建掩码
			mask := net.CIDRMask(maskBits, 32)
			// 计算网络地址
			networkIP := net.IP(make([]byte, 4))
			for i := 0; i < 4; i++ {
				networkIP[i] = ip[i] & mask[i]
			}
			return fmt.Sprintf("%s/%d", networkIP.String(), maskBits)
		}
	}

	// 其他情况返回原始目标
	return target
}

// IPToString 将IP地址转换为字符串
func IPToString(ip net.IP) string {
	if ip == nil {
		return ""
	}
	return ip.String()
}

// StringToIP 将字符串转换为IP地址
func StringToIP(s string) net.IP {
	return net.ParseIP(s)
}

// GetLocalIPAddresses 获取本地所有IP地址
func GetLocalIPAddresses() ([]net.IP, error) {
	var result []net.IP

	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("获取网络接口失败: %w", err)
	}

	for _, iface := range interfaces {
		// 跳过禁用的接口
		if iface.Flags&net.FlagUp == 0 {
			continue
		}

		// 跳过回环接口
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}

			if ip != nil && !ip.IsLoopback() && ip.To4() != nil {
				result = append(result, ip)
			}
		}
	}

	return result, nil
}

// GetLocalIP 获取本地IP地址列表
func GetLocalIP() ([]string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("获取网络接口失败: %w", err)
	}

	var result []string
	for _, iface := range interfaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if ok && !ipNet.IP.IsLoopback() && ipNet.IP.To4() != nil {
				result = append(result, ipNet.IP.String())
			}
		}
	}

	return result, nil
}

// ParseIPRange 解析IP范围字符串，如 "192.168.1.1-192.168.1.100"
func ParseIPRange(ipRange string) ([]net.IP, error) {
	var result []net.IP

	parts := strings.Split(ipRange, "-")
	if len(parts) != 2 {
		return nil, fmt.Errorf("无效的IP范围格式")
	}

	startIP := net.ParseIP(strings.TrimSpace(parts[0]))
	endIP := net.ParseIP(strings.TrimSpace(parts[1]))

	if startIP == nil || endIP == nil {
		return nil, fmt.Errorf("无效的IP地址")
	}

	// 确保是IPv4地址
	startIP = startIP.To4()
	endIP = endIP.To4()

	if startIP == nil || endIP == nil {
		return nil, fmt.Errorf("目前仅支持IPv4地址范围")
	}

	// 生成IP范围
	for ip := startIP; !ip.Equal(endIP); ip = incrementIP(ip) {
		result = append(result, net.ParseIP(ip.String()))
	}
	// 添加最后一个IP
	result = append(result, net.ParseIP(endIP.String()))

	return result, nil
}

// GetIPOctets 获取IP地址的各个八位组
func GetIPOctets(ip net.IP) ([]int, error) {
	ip = ip.To4()
	if ip == nil {
		return nil, fmt.Errorf("不是有效的IPv4地址")
	}

	octets := make([]int, 4)
	for i := 0; i < 4; i++ {
		octets[i] = int(ip[i])
	}

	return octets, nil
}

// ParseIPFromString 从字符串解析IP地址，支持IP、域名、CIDR和范围格式
func ParseIPFromString(s string) ([]net.IP, error) {
	// 尝试作为CIDR解析
	if strings.Contains(s, "/") {
		return GetIPsFromTarget(s)
	}

	// 尝试作为IP范围解析
	if strings.Contains(s, "-") {
		return ParseIPRange(s)
	}

	// 尝试作为单个IP或域名解析
	return GetIPsFromTarget(s)
}

// ValidateIPAddress 验证IP地址是否有效
func ValidateIPAddress(ip string) bool {
	parsedIP := net.ParseIP(ip)
	return parsedIP != nil
}

// GetIPClass 获取IP地址的类别
func GetIPClass(ip net.IP) string {
	ip = ip.To4()
	if ip == nil {
		return "Unknown"
	}

	octet := int(ip[0])

	if octet >= 0 && octet <= 127 {
		return "A"
	} else if octet >= 128 && octet <= 191 {
		return "B"
	} else if octet >= 192 && octet <= 223 {
		return "C"
	} else if octet >= 224 && octet <= 239 {
		return "D" // 多播地址
	} else if octet >= 240 && octet <= 255 {
		return "E" // 保留地址
	}

	return "Unknown"
}

// IsIPInRange 判断IP是否在指定范围内
func IsIPInRange(ip net.IP, start, end net.IP) bool {
	ip = ip.To4()
	start = start.To4()
	end = end.To4()

	if ip == nil || start == nil || end == nil {
		return false
	}

	// 比较每个八位组
	for i := 0; i < 4; i++ {
		if ip[i] < start[i] || ip[i] > end[i] {
			return false
		}
	}

	return true
}
