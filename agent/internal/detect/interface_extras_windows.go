//go:build windows

package detect

import (
	"fmt"
	"sort"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

func loadInterfaceExtras() (map[int]interfaceExtras, map[string]interfaceExtras, []string) {
	const family = windows.AF_UNSPEC
	flags := uint32(windows.GAA_FLAG_INCLUDE_GATEWAYS | windows.GAA_FLAG_INCLUDE_ALL_INTERFACES)

	var head *windows.IpAdapterAddresses
	var buf []byte
	for tries := 0; tries < 3; tries++ {
		var size uint32
		err := windows.GetAdaptersAddresses(family, flags, 0, nil, &size)
		if err != nil && err != windows.ERROR_BUFFER_OVERFLOW {
			return nil, nil, []string{fmt.Sprintf("GetAdaptersAddresses 失败: %v", err)}
		}
		if size == 0 {
			return nil, nil, []string{"GetAdaptersAddresses 失败: buffer size is 0"}
		}

		buf = make([]byte, size)
		head = (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0]))
		err = windows.GetAdaptersAddresses(family, flags, 0, head, &size)
		if err == nil {
			break
		}
		if err == windows.ERROR_BUFFER_OVERFLOW {
			head = nil
			continue
		}
		return nil, nil, []string{fmt.Sprintf("GetAdaptersAddresses 失败: %v", err)}
	}
	if head == nil {
		return nil, nil, []string{"GetAdaptersAddresses 失败: buffer overflow retries exceeded"}
	}

	byIndex := make(map[int]interfaceExtras)
	byName := make(map[string]interfaceExtras)
	for adapter := head; adapter != nil; adapter = adapter.Next {
		name := strings.TrimSpace(windows.UTF16PtrToString(adapter.FriendlyName))
		suffix := strings.TrimSpace(windows.UTF16PtrToString(adapter.DnsSuffix))
		description := strings.TrimSpace(windows.UTF16PtrToString(adapter.Description))

		dnsServers := collectDNSServers(adapter.FirstDnsServerAddress)
		gateways := collectGateways(adapter.FirstGatewayAddress)

		var dhcpv4Server string
		if ip := adapter.Dhcpv4Server.IP(); ip != nil && !ip.IsUnspecified() {
			dhcpv4Server = ip.String()
		}
		var dhcpv6Server string
		if ip := adapter.Dhcpv6Server.IP(); ip != nil && !ip.IsUnspecified() {
			dhcpv6Server = ip.String()
		}

		extras := interfaceExtras{
			DNSSuffix:    suffix,
			DNSServers:   dnsServers,
			Gateways:     gateways,
			Description:  description,
			DHCPv4Server: dhcpv4Server,
			DHCPv6Server: dhcpv6Server,
			Connection:   adapter.ConnectionType,
			IfType:       adapter.IfType,
			OperStatus:   adapter.OperStatus,
			IPv4Metric:   adapter.Ipv4Metric,
			IPv6Metric:   adapter.Ipv6Metric,
			TunnelType:   adapter.TunnelType,
			TxLinkSpeed:  adapter.TransmitLinkSpeed,
			RxLinkSpeed:  adapter.ReceiveLinkSpeed,
		}

		if adapter.IfIndex != 0 {
			idx := int(adapter.IfIndex)
			byIndex[idx] = mergeInterfaceExtras(byIndex[idx], extras)
		}
		if adapter.Ipv6IfIndex != 0 {
			idx := int(adapter.Ipv6IfIndex)
			byIndex[idx] = mergeInterfaceExtras(byIndex[idx], extras)
		}
		if name != "" {
			byName[name] = mergeInterfaceExtras(byName[name], extras)
		}
	}

	if len(byIndex) == 0 {
		byIndex = nil
	}
	if len(byName) == 0 {
		byName = nil
	}
	return byIndex, byName, nil
}

func mergeInterfaceExtras(dst, src interfaceExtras) interfaceExtras {
	if dst.DNSSuffix == "" {
		dst.DNSSuffix = src.DNSSuffix
	}
	dst.DNSServers = mergeStringSet(dst.DNSServers, src.DNSServers)
	dst.Gateways = mergeStringSet(dst.Gateways, src.Gateways)
	if dst.Description == "" {
		dst.Description = src.Description
	}
	if dst.DHCPv4Server == "" {
		dst.DHCPv4Server = src.DHCPv4Server
	}
	if dst.DHCPv6Server == "" {
		dst.DHCPv6Server = src.DHCPv6Server
	}
	if dst.Connection == 0 {
		dst.Connection = src.Connection
	}
	if dst.IfType == 0 {
		dst.IfType = src.IfType
	}
	if dst.OperStatus == 0 {
		dst.OperStatus = src.OperStatus
	}
	if dst.IPv4Metric == 0 {
		dst.IPv4Metric = src.IPv4Metric
	}
	if dst.IPv6Metric == 0 {
		dst.IPv6Metric = src.IPv6Metric
	}
	if dst.TunnelType == 0 {
		dst.TunnelType = src.TunnelType
	}
	if src.TxLinkSpeed > dst.TxLinkSpeed {
		dst.TxLinkSpeed = src.TxLinkSpeed
	}
	if src.RxLinkSpeed > dst.RxLinkSpeed {
		dst.RxLinkSpeed = src.RxLinkSpeed
	}
	return dst
}

func mergeStringSet(dst, src []string) []string {
	if len(src) == 0 {
		return dst
	}
	if len(dst) == 0 {
		dst = append([]string{}, src...)
		sort.Strings(dst)
		dst = dedupeSortedStrings(dst)
		return dst
	}
	merged := make(map[string]struct{}, len(dst)+len(src))
	for _, v := range dst {
		if v == "" {
			continue
		}
		merged[v] = struct{}{}
	}
	for _, v := range src {
		if v == "" {
			continue
		}
		merged[v] = struct{}{}
	}
	out := make([]string, 0, len(merged))
	for v := range merged {
		out = append(out, v)
	}
	sort.Strings(out)
	if len(out) == 0 {
		return nil
	}
	return out
}

func dedupeSortedStrings(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := in[:0]
	var prev string
	for i, v := range in {
		if v == "" {
			continue
		}
		if i > 0 && v == prev {
			continue
		}
		out = append(out, v)
		prev = v
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func collectDNSServers(head *windows.IpAdapterDnsServerAdapter) []string {
	seen := make(map[string]struct{}, 4)
	out := make([]string, 0, 4)
	for cur := head; cur != nil; cur = cur.Next {
		ip := cur.Address.IP()
		if ip == nil || ip.IsUnspecified() {
			continue
		}
		value := ip.String()
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	if len(out) == 0 {
		return nil
	}
	return out
}

func collectGateways(head *windows.IpAdapterGatewayAddress) []string {
	seen := make(map[string]struct{}, 4)
	out := make([]string, 0, 4)
	for cur := head; cur != nil; cur = cur.Next {
		ip := cur.Address.IP()
		if ip == nil || ip.IsUnspecified() {
			continue
		}
		value := ip.String()
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	if len(out) == 0 {
		return nil
	}
	return out
}
