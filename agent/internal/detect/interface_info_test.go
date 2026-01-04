package detect

import (
	"bytes"
	"errors"
	"net"
	"strings"
	"testing"
)

func TestWriteInterfaceInfoWithListErrorWritesFallback(t *testing.T) {
	var buf bytes.Buffer
	notes, err := writeInterfaceInfoWith(&buf, func() ([]net.Interface, error) {
		return nil, errors.New("boom")
	}, func(_ net.Interface) ([]net.Addr, error) {
		return nil, nil
	})
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "failed to enumerate interfaces") {
		t.Fatalf("expected fallback message, got %q", out)
	}
	if len(notes) != 1 || !strings.Contains(notes[0], "接口枚举失败") {
		t.Fatalf("expected single note about failure, got %#v", notes)
	}
}

func TestWriteInterfaceInfoWithAddrsErrorStillWritesInterface(t *testing.T) {
	ifaces := []net.Interface{
		{Name: "b", Index: 2, MTU: 1500, HardwareAddr: net.HardwareAddr{0x0a, 0x0b, 0x0c}},
		{Name: "a", Index: 1, MTU: 1400, Flags: net.FlagUp | net.FlagMulticast},
	}

	var buf bytes.Buffer
	notes, err := writeInterfaceInfoWith(&buf, func() ([]net.Interface, error) {
		return ifaces, nil
	}, func(iface net.Interface) ([]net.Addr, error) {
		if iface.Name == "a" {
			return nil, errors.New("addr failed")
		}
		return []net.Addr{
			&net.IPNet{IP: net.IPv4(10, 0, 0, 1), Mask: net.CIDRMask(24, 32)},
		}, nil
	})
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	out := buf.String()
	if strings.Index(out, "* a") == -1 || strings.Index(out, "* b") == -1 {
		t.Fatalf("expected both interfaces in output, got %q", out)
	}
	if strings.Index(out, "* a") > strings.Index(out, "* b") {
		t.Fatalf("expected deterministic ordering by name, got %q", out)
	}
	if !strings.Contains(out, "addrs_error:") {
		t.Fatalf("expected addrs error line, got %q", out)
	}
	if !strings.Contains(out, "addr: 10.0.0.1/24") {
		t.Fatalf("expected address line, got %q", out)
	}
	found := false
	for _, note := range notes {
		if strings.Contains(note, "接口地址采集失败") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected note about addrs failure, got %#v", notes)
	}
}

func TestWriteInterfaceInfoWithNilWriterFails(t *testing.T) {
	_, err := writeInterfaceInfoWith(nil, func() ([]net.Interface, error) { return nil, nil }, func(_ net.Interface) ([]net.Addr, error) { return nil, nil })
	if err == nil {
		t.Fatalf("expected error for nil writer")
	}
}

func TestWriteInterfaceInfoWithExtrasWritesDNSAndGateway(t *testing.T) {
	prev := loadInterfaceExtrasFn
	loadInterfaceExtrasFn = func() (map[int]interfaceExtras, map[string]interfaceExtras, []string) {
		return map[int]interfaceExtras{
				1: {DNSSuffix: "corp.example", DNSServers: []string{"1.1.1.1"}, Gateways: []string{"10.0.0.254"}},
			},
			nil,
			nil
	}
	t.Cleanup(func() {
		loadInterfaceExtrasFn = prev
	})

	ifaces := []net.Interface{
		{Name: "a", Index: 1, MTU: 1500},
	}

	var buf bytes.Buffer
	_, err := writeInterfaceInfoWith(&buf, func() ([]net.Interface, error) {
		return ifaces, nil
	}, func(_ net.Interface) ([]net.Addr, error) {
		return []net.Addr{
			&net.IPNet{IP: net.IPv4(10, 0, 0, 1), Mask: net.CIDRMask(24, 32)},
		}, nil
	})
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "dns_suffix: corp.example") {
		t.Fatalf("expected dns suffix, got %q", out)
	}
	if !strings.Contains(out, "dns_server: 1.1.1.1") {
		t.Fatalf("expected dns server, got %q", out)
	}
	if !strings.Contains(out, "gateway: 10.0.0.254") {
		t.Fatalf("expected gateway, got %q", out)
	}
}

func TestWriteInterfaceInfoWithExtrasStillWritesWhenNoAddrs(t *testing.T) {
	prev := loadInterfaceExtrasFn
	loadInterfaceExtrasFn = func() (map[int]interfaceExtras, map[string]interfaceExtras, []string) {
		return map[int]interfaceExtras{
				1: {DNSServers: []string{"1.1.1.1"}, Gateways: []string{"10.0.0.254"}},
			},
			nil,
			nil
	}
	t.Cleanup(func() {
		loadInterfaceExtrasFn = prev
	})

	ifaces := []net.Interface{
		{Name: "a", Index: 1, MTU: 1500},
	}

	var buf bytes.Buffer
	_, err := writeInterfaceInfoWith(&buf, func() ([]net.Interface, error) {
		return ifaces, nil
	}, func(_ net.Interface) ([]net.Addr, error) {
		return nil, nil
	})
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "addr: (none)") {
		t.Fatalf("expected none address, got %q", out)
	}
	if !strings.Contains(out, "dns_server: 1.1.1.1") {
		t.Fatalf("expected dns server, got %q", out)
	}
	if !strings.Contains(out, "gateway: 10.0.0.254") {
		t.Fatalf("expected gateway, got %q", out)
	}
}

func TestWriteInterfaceInfoWithExtrasWritesDHCPAndLinkSpeed(t *testing.T) {
	prev := loadInterfaceExtrasFn
	loadInterfaceExtrasFn = func() (map[int]interfaceExtras, map[string]interfaceExtras, []string) {
		return map[int]interfaceExtras{
				1: {
					Description:  "Intel(R) Ethernet Connection",
					DHCPv4Server: "10.0.0.2",
					DHCPv6Server: "fe80::1",
					Connection:   1,
					IfType:       6,
					OperStatus:   1,
					IPv4Metric:   10,
					IPv6Metric:   20,
					TunnelType:   14,
					TxLinkSpeed:  1_000_000_000,
					RxLinkSpeed:  10_000_000,
				},
			},
			nil,
			nil
	}
	t.Cleanup(func() {
		loadInterfaceExtrasFn = prev
	})

	ifaces := []net.Interface{
		{Name: "a", Index: 1, MTU: 1500},
	}

	var buf bytes.Buffer
	_, err := writeInterfaceInfoWith(&buf, func() ([]net.Interface, error) {
		return ifaces, nil
	}, func(_ net.Interface) ([]net.Addr, error) {
		return nil, nil
	})
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "description: Intel(R) Ethernet Connection") {
		t.Fatalf("expected description, got %q", out)
	}
	if !strings.Contains(out, "dhcpv4_server: 10.0.0.2") {
		t.Fatalf("expected dhcpv4 server, got %q", out)
	}
	if !strings.Contains(out, "dhcpv6_server: fe80::1") {
		t.Fatalf("expected dhcpv6 server, got %q", out)
	}
	if !strings.Contains(out, "if_type: 6 (ethernet)") {
		t.Fatalf("expected if_type label, got %q", out)
	}
	if !strings.Contains(out, "oper_status: 1 (up)") {
		t.Fatalf("expected oper_status label, got %q", out)
	}
	if !strings.Contains(out, "connection_type: 1 (dedicated)") {
		t.Fatalf("expected connection_type label, got %q", out)
	}
	if !strings.Contains(out, "ipv4_metric: 10") {
		t.Fatalf("expected ipv4 metric, got %q", out)
	}
	if !strings.Contains(out, "ipv6_metric: 20") {
		t.Fatalf("expected ipv6 metric, got %q", out)
	}
	if !strings.Contains(out, "tunnel_type: 14 (teredo)") {
		t.Fatalf("expected tunnel type label, got %q", out)
	}
	if !strings.Contains(out, "link_speed_tx_bps: 1000000000 (1Gbps)") {
		t.Fatalf("expected tx link speed, got %q", out)
	}
	if !strings.Contains(out, "link_speed_rx_bps: 10000000 (10Mbps)") {
		t.Fatalf("expected rx link speed, got %q", out)
	}
}

func TestWriteInterfaceInfoWithExtrasWritesZeroMetrics(t *testing.T) {
	prev := loadInterfaceExtrasFn
	loadInterfaceExtrasFn = func() (map[int]interfaceExtras, map[string]interfaceExtras, []string) {
		return map[int]interfaceExtras{
				1: {
					IPv4Metric: 0,
					IPv6Metric: 0,
				},
			},
			nil,
			nil
	}
	t.Cleanup(func() {
		loadInterfaceExtrasFn = prev
	})

	ifaces := []net.Interface{
		{Name: "a", Index: 1},
	}

	var buf bytes.Buffer
	_, err := writeInterfaceInfoWith(&buf, func() ([]net.Interface, error) {
		return ifaces, nil
	}, func(_ net.Interface) ([]net.Addr, error) {
		return nil, nil
	})
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "ipv4_metric: 0") {
		t.Fatalf("expected ipv4 metric=0, got %q", out)
	}
	if !strings.Contains(out, "ipv6_metric: 0") {
		t.Fatalf("expected ipv6 metric=0, got %q", out)
	}
}
