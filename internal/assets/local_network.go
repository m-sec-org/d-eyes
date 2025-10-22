package assets

import (
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/m-sec-org/d-eyes/internal/assets/utils"
)

// LocalNetwork 描述从本机接口派生的一个网络
type LocalNetwork struct {
	Interface string
	IP        net.IP
	Mask      net.IPMask
	CIDR      string
}

// DiscoverLocalNetworks 枚举本机接口并推导 IPv4 网络段
func DiscoverLocalNetworks(includeLoopback bool) ([]LocalNetwork, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("枚举本地网络接口失败: %w", err)
	}

	networkMap := make(map[string]LocalNetwork)

	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		if !includeLoopback && iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ip, ipNet := parseIPv4(addr)
			if ip == nil || ipNet == nil {
				continue
			}

			cidr := ipNet.String()
			if existing, ok := networkMap[cidr]; ok {
				// 保留首个非零 IP 作为代表
				if existing.IP == nil || existing.IP.IsUnspecified() {
					existing.IP = ip
					networkMap[cidr] = existing
				}
				continue
			}

			networkMap[cidr] = LocalNetwork{
				Interface: iface.Name,
				IP:        ip,
				Mask:      ipNet.Mask,
				CIDR:      cidr,
			}
		}
	}

	result := make([]LocalNetwork, 0, len(networkMap))
	for _, nw := range networkMap {
		result = append(result, nw)
	}

	sort.Slice(result, func(i, j int) bool {
		if result[i].Interface == result[j].Interface {
			return result[i].CIDR < result[j].CIDR
		}
		return result[i].Interface < result[j].Interface
	})

	return result, nil
}

func parseIPv4(addr net.Addr) (net.IP, *net.IPNet) {
	switch v := addr.(type) {
	case *net.IPNet:
		if v == nil {
			return nil, nil
		}
		raw := v.IP.To4()
		if raw == nil || utils.IsLoopbackIP(raw) {
			return nil, nil
		}
		ip := append(net.IP(nil), raw...)
		if ip == nil || utils.IsLoopbackIP(ip) {
			return nil, nil
		}
		return ip, &net.IPNet{IP: ip.Mask(v.Mask), Mask: v.Mask}
	case *net.IPAddr:
		if v == nil {
			return nil, nil
		}
		raw := v.IP.To4()
		if raw == nil || utils.IsLoopbackIP(raw) {
			return nil, nil
		}
		ip := append(net.IP(nil), raw...)
		if ip == nil || utils.IsLoopbackIP(ip) {
			return nil, nil
		}
		mask := net.CIDRMask(24, 32)
		return ip, &net.IPNet{IP: ip.Mask(mask), Mask: mask}
	default:
		return nil, nil
	}
}

// FormatLocalNetworks 将本地网络列表转换为可读字符串
func FormatLocalNetworks(networks []LocalNetwork) string {
	if len(networks) == 0 {
		return ""
	}
	parts := make([]string, 0, len(networks))
	for _, nw := range networks {
		parts = append(parts, fmt.Sprintf("%s:%s", nw.Interface, nw.CIDR))
	}
	return strings.Join(parts, ", ")
}
