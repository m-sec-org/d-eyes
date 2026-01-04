package detect

import (
	"errors"
	"fmt"
	"io"
	"net"
	"sort"
	"strings"
)

type interfaceInfo struct {
	Index        int
	Name         string
	MTU          int
	HardwareAddr string
	Flags        []string
	Addrs        []string
	AddrsError   string
	ExtrasLoaded bool
	DNSSuffix    string
	DNSServers   []string
	Gateways     []string
	Description  string
	DHCPv4Server string
	DHCPv6Server string
	Connection   uint32
	IfType       uint32
	OperStatus   uint32
	IPv4Metric   uint32
	IPv6Metric   uint32
	TunnelType   uint32
	TxLinkSpeed  uint64
	RxLinkSpeed  uint64
}

type interfaceLister func() ([]net.Interface, error)

type interfaceAddrsFunc func(net.Interface) ([]net.Addr, error)

type interfaceExtras struct {
	DNSSuffix    string
	DNSServers   []string
	Gateways     []string
	Description  string
	DHCPv4Server string
	DHCPv6Server string
	Connection   uint32
	IfType       uint32
	OperStatus   uint32
	IPv4Metric   uint32
	IPv6Metric   uint32
	TunnelType   uint32
	TxLinkSpeed  uint64
	RxLinkSpeed  uint64
}

var loadInterfaceExtrasFn = loadInterfaceExtras

func writeInterfaceInfo(w io.Writer) ([]string, error) {
	return writeInterfaceInfoWith(w, net.Interfaces, func(iface net.Interface) ([]net.Addr, error) {
		return iface.Addrs()
	})
}

func writeInterfaceInfoWith(w io.Writer, listFn interfaceLister, addrsFn interfaceAddrsFunc) ([]string, error) {
	if w == nil {
		return nil, errors.New("interface info: writer is nil")
	}
	if listFn == nil {
		return nil, errors.New("interface info: list func is nil")
	}
	if addrsFn == nil {
		return nil, errors.New("interface info: addrs func is nil")
	}

	ifaces, err := listFn()
	if err != nil {
		if _, werr := fmt.Fprintf(w, "    (failed to enumerate interfaces: %v)\n", err); werr != nil {
			return nil, werr
		}
		return []string{fmt.Sprintf("接口枚举失败: %v", err)}, nil
	}

	extrasByIndex, extrasByName, extraNotes := loadInterfaceExtrasFn()

	infos := make([]interfaceInfo, 0, len(ifaces))
	notes := append([]string{}, extraNotes...)
	for _, iface := range ifaces {
		info := interfaceInfo{
			Index:        iface.Index,
			Name:         iface.Name,
			MTU:          iface.MTU,
			HardwareAddr: iface.HardwareAddr.String(),
			Flags:        formatNetInterfaceFlags(iface.Flags),
		}

		addrs, err := addrsFn(iface)
		if err != nil {
			info.AddrsError = err.Error()
			notes = append(notes, fmt.Sprintf("接口地址采集失败(name=%s index=%d): %v", iface.Name, iface.Index, err))
		} else {
			for _, addr := range addrs {
				if addr == nil {
					continue
				}
				info.Addrs = append(info.Addrs, addr.String())
			}
			sort.Strings(info.Addrs)
			if len(info.Addrs) == 0 {
				info.Addrs = nil
			}
		}

		if extras, ok := extrasByIndex[iface.Index]; ok {
			info.ExtrasLoaded = true
			info.DNSSuffix = extras.DNSSuffix
			info.DNSServers = append([]string{}, extras.DNSServers...)
			info.Gateways = append([]string{}, extras.Gateways...)
			info.Description = extras.Description
			info.DHCPv4Server = extras.DHCPv4Server
			info.DHCPv6Server = extras.DHCPv6Server
			info.Connection = extras.Connection
			info.IfType = extras.IfType
			info.OperStatus = extras.OperStatus
			info.IPv4Metric = extras.IPv4Metric
			info.IPv6Metric = extras.IPv6Metric
			info.TunnelType = extras.TunnelType
			info.TxLinkSpeed = extras.TxLinkSpeed
			info.RxLinkSpeed = extras.RxLinkSpeed
		} else if extras, ok := extrasByName[iface.Name]; ok {
			info.ExtrasLoaded = true
			info.DNSSuffix = extras.DNSSuffix
			info.DNSServers = append([]string{}, extras.DNSServers...)
			info.Gateways = append([]string{}, extras.Gateways...)
			info.Description = extras.Description
			info.DHCPv4Server = extras.DHCPv4Server
			info.DHCPv6Server = extras.DHCPv6Server
			info.Connection = extras.Connection
			info.IfType = extras.IfType
			info.OperStatus = extras.OperStatus
			info.IPv4Metric = extras.IPv4Metric
			info.IPv6Metric = extras.IPv6Metric
			info.TunnelType = extras.TunnelType
			info.TxLinkSpeed = extras.TxLinkSpeed
			info.RxLinkSpeed = extras.RxLinkSpeed
		}
		if len(info.DNSServers) == 0 {
			info.DNSServers = nil
		}
		if len(info.Gateways) == 0 {
			info.Gateways = nil
		}

		infos = append(infos, info)
	}

	sort.Slice(infos, func(i, j int) bool {
		if infos[i].Name == infos[j].Name {
			return infos[i].Index < infos[j].Index
		}
		return infos[i].Name < infos[j].Name
	})

	if len(infos) == 0 {
		if _, err := io.WriteString(w, "    (no interfaces found)\n"); err != nil {
			return nil, err
		}
		return notes, nil
	}

	for _, info := range infos {
		if err := writeInterfaceInfoEntry(w, info); err != nil {
			return nil, err
		}
	}

	return notes, nil
}

func formatNetInterfaceFlags(flags net.Flags) []string {
	out := make([]string, 0, 4)
	if flags&net.FlagUp != 0 {
		out = append(out, "up")
	}
	if flags&net.FlagBroadcast != 0 {
		out = append(out, "broadcast")
	}
	if flags&net.FlagLoopback != 0 {
		out = append(out, "loopback")
	}
	if flags&net.FlagPointToPoint != 0 {
		out = append(out, "pointtopoint")
	}
	if flags&net.FlagMulticast != 0 {
		out = append(out, "multicast")
	}
	return out
}

func writeInterfaceInfoEntry(w io.Writer, info interfaceInfo) error {
	name := strings.TrimSpace(info.Name)
	if name == "" {
		name = fmt.Sprintf("<iface-%d>", info.Index)
	}

	fields := make([]string, 0, 4)
	fields = append(fields, fmt.Sprintf("index=%d", info.Index))
	if info.MTU > 0 {
		fields = append(fields, fmt.Sprintf("mtu=%d", info.MTU))
	}
	if info.HardwareAddr != "" {
		fields = append(fields, fmt.Sprintf("mac=%s", info.HardwareAddr))
	}
	if len(info.Flags) > 0 {
		fields = append(fields, fmt.Sprintf("flags=%s", strings.Join(info.Flags, "|")))
	}

	if _, err := fmt.Fprintf(w, "    * %s (%s)\n", name, strings.Join(fields, ", ")); err != nil {
		return err
	}

	if info.AddrsError != "" {
		if _, err := fmt.Fprintf(w, "        - addrs_error: %s\n", info.AddrsError); err != nil {
			return err
		}
	}

	if len(info.Addrs) == 0 {
		if _, err := io.WriteString(w, "        - addr: (none)\n"); err != nil {
			return err
		}
	} else {
		for _, addr := range info.Addrs {
			if _, err := fmt.Fprintf(w, "        - addr: %s\n", addr); err != nil {
				return err
			}
		}
	}

	if info.DNSSuffix != "" {
		if _, err := fmt.Fprintf(w, "        - dns_suffix: %s\n", info.DNSSuffix); err != nil {
			return err
		}
	}
	for _, dns := range info.DNSServers {
		if _, err := fmt.Fprintf(w, "        - dns_server: %s\n", dns); err != nil {
			return err
		}
	}
	for _, gw := range info.Gateways {
		if _, err := fmt.Fprintf(w, "        - gateway: %s\n", gw); err != nil {
			return err
		}
	}
	if info.Description != "" {
		if _, err := fmt.Fprintf(w, "        - description: %s\n", info.Description); err != nil {
			return err
		}
	}
	if info.DHCPv4Server != "" {
		if _, err := fmt.Fprintf(w, "        - dhcpv4_server: %s\n", info.DHCPv4Server); err != nil {
			return err
		}
	}
	if info.DHCPv6Server != "" {
		if _, err := fmt.Fprintf(w, "        - dhcpv6_server: %s\n", info.DHCPv6Server); err != nil {
			return err
		}
	}
	if info.IfType != 0 {
		if _, err := fmt.Fprintf(w, "        - if_type: %d (%s)\n", info.IfType, ifTypeLabel(info.IfType)); err != nil {
			return err
		}
	}
	if info.OperStatus != 0 {
		if _, err := fmt.Fprintf(w, "        - oper_status: %d (%s)\n", info.OperStatus, operStatusLabel(info.OperStatus)); err != nil {
			return err
		}
	}
	if info.Connection != 0 {
		if _, err := fmt.Fprintf(w, "        - connection_type: %d (%s)\n", info.Connection, connectionTypeLabel(info.Connection)); err != nil {
			return err
		}
	}
	if info.ExtrasLoaded {
		if _, err := fmt.Fprintf(w, "        - ipv4_metric: %d\n", info.IPv4Metric); err != nil {
			return err
		}
	}
	if info.ExtrasLoaded {
		if _, err := fmt.Fprintf(w, "        - ipv6_metric: %d\n", info.IPv6Metric); err != nil {
			return err
		}
	}
	if info.TunnelType != 0 {
		if _, err := fmt.Fprintf(w, "        - tunnel_type: %d (%s)\n", info.TunnelType, tunnelTypeLabel(info.TunnelType)); err != nil {
			return err
		}
	}
	if info.TxLinkSpeed > 0 {
		if _, err := fmt.Fprintf(w, "        - link_speed_tx_bps: %d (%s)\n", info.TxLinkSpeed, formatBitRate(info.TxLinkSpeed)); err != nil {
			return err
		}
	}
	if info.RxLinkSpeed > 0 {
		if _, err := fmt.Fprintf(w, "        - link_speed_rx_bps: %d (%s)\n", info.RxLinkSpeed, formatBitRate(info.RxLinkSpeed)); err != nil {
			return err
		}
	}
	return nil
}

func ifTypeLabel(ifType uint32) string {
	switch ifType {
	case 6:
		return "ethernet"
	case 9:
		return "tokenring"
	case 23:
		return "ppp"
	case 24:
		return "loopback"
	case 37:
		return "atm"
	case 71:
		return "wifi"
	case 131:
		return "tunnel"
	case 144:
		return "firewire"
	case 1:
		return "other"
	default:
		return "unknown"
	}
}

func operStatusLabel(status uint32) string {
	switch status {
	case 1:
		return "up"
	case 2:
		return "down"
	case 3:
		return "testing"
	case 4:
		return "unknown"
	case 5:
		return "dormant"
	case 6:
		return "not-present"
	case 7:
		return "lower-layer-down"
	default:
		return "unknown"
	}
}

func connectionTypeLabel(value uint32) string {
	switch value {
	case 0:
		return "unknown"
	case 1:
		return "dedicated"
	case 2:
		return "passive"
	case 3:
		return "demand"
	case 4:
		return "maximum"
	default:
		return "unknown"
	}
}

func tunnelTypeLabel(value uint32) string {
	switch value {
	case 0:
		return "none"
	case 1:
		return "other"
	case 2:
		return "direct"
	case 11:
		return "6to4"
	case 13:
		return "isatap"
	case 14:
		return "teredo"
	case 15:
		return "iphttps"
	default:
		return "unknown"
	}
}

func formatBitRate(bps uint64) string {
	if bps == 0 {
		return ""
	}
	const (
		kbps = 1000
		mbps = 1000 * kbps
		gbps = 1000 * mbps
	)
	switch {
	case bps%gbps == 0:
		return fmt.Sprintf("%dGbps", bps/gbps)
	case bps >= gbps:
		return fmt.Sprintf("%.1fGbps", float64(bps)/float64(gbps))
	case bps%mbps == 0:
		return fmt.Sprintf("%dMbps", bps/mbps)
	case bps >= mbps:
		return fmt.Sprintf("%.1fMbps", float64(bps)/float64(mbps))
	case bps%kbps == 0:
		return fmt.Sprintf("%dKbps", bps/kbps)
	case bps >= kbps:
		return fmt.Sprintf("%.1fKbps", float64(bps)/float64(kbps))
	default:
		return fmt.Sprintf("%dbps", bps)
	}
}
