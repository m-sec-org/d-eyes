//go:build integration

package assets

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/pkg/errors"

	"github.com/m-sec-org/d-eyes/internal/assets/utils"
)

// ICMPHostDiscoverer 基于ICMP的主机发现实现
type ICMPHostDiscoverer struct {
	timeout time.Duration
	workers int
}

// NewICMPHostDiscoverer 创建ICMP主机发现器
func NewICMPHostDiscoverer(timeout time.Duration, workers int) *ICMPHostDiscoverer {
	return &ICMPHostDiscoverer{
		timeout: timeout,
		workers: workers,
	}
}

// Discover 实现HostDetector接口
func (d *ICMPHostDiscoverer) Discover(ctx context.Context, target string, options ScanOptions) ([]HostInfo, error) {
	var hosts []HostInfo
	var mu sync.Mutex
	var wg sync.WaitGroup

	_, ipnet, err := utils.ParseCIDR(target)
	if err != nil {
		return nil, errors.Wrap(err, "解析目标失败")
	}

	ipRanges := utils.GenerateIPRange(ipnet)

	ipChan := make(chan net.IP, len(ipRanges))
	for _, ip := range ipRanges {
		ipChan <- ip
	}
	close(ipChan)

	workerSem := make(chan struct{}, d.workers)

	for ip := range ipChan {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case workerSem <- struct{}{}:
			wg.Add(1)
			go func(ip net.IP) {
				defer wg.Done()
				defer func() { <-workerSem }()

				host, err := d.pingHost(ctx, ip, options)
				if err == nil && host != nil {
					mu.Lock()
					hosts = append(hosts, *host)
					mu.Unlock()
				}
			}(ip)
		}
	}

	wg.Wait()
	return hosts, nil
}

func (d *ICMPHostDiscoverer) pingHost(ctx context.Context, ip net.IP, options ScanOptions) (*HostInfo, error) {
	var cmd *exec.Cmd

	switch runtime.GOOS {
	case "windows":
		cmd = exec.CommandContext(ctx, "ping", "-n", "1", "-w", fmt.Sprintf("%d", int(d.timeout.Milliseconds())), ip.String())
	case "darwin":
		cmd = exec.CommandContext(ctx, "ping", "-c", "1", "-t", fmt.Sprintf("%d", int(d.timeout.Seconds())), ip.String())
	default:
		cmd = exec.CommandContext(ctx, "ping", "-c", "1", "-W", fmt.Sprintf("%d", int(d.timeout.Seconds())), ip.String())
	}

	_, err := cmd.CombinedOutput()
	if err != nil {
		return nil, errors.New("主机不可达")
	}

	hostname := ""
	if options.ResolveHostname {
		hostnames, err := net.LookupAddr(ip.String())
		if err == nil && len(hostnames) > 0 {
			hostname = strings.TrimSuffix(hostnames[0], ".")
		}
	}

	host := &HostInfo{
		IP:       ip,
		Hostname: hostname,
		Status:   "up",
		LastSeen: time.Now(),
	}

	return host, nil
}

// TCPHostDiscoverer 基于TCP的主机发现实现
type TCPHostDiscoverer struct {
	timeout  time.Duration
	workers  int
	portList []int
}

func NewTCPHostDiscoverer(timeout time.Duration, workers int, portList []int) *TCPHostDiscoverer {
	if len(portList) == 0 {
		portList = utils.GetCommonPorts()[:3]
	}
	return &TCPHostDiscoverer{
		timeout:  timeout,
		workers:  workers,
		portList: portList,
	}
}

func (d *TCPHostDiscoverer) Discover(ctx context.Context, target string, options ScanOptions) ([]HostInfo, error) {
	var hosts []HostInfo
	var mu sync.Mutex
	var wg sync.WaitGroup

	_, ipnet, err := utils.ParseCIDR(target)
	if err != nil {
		return nil, errors.Wrap(err, "解析目标失败")
	}

	ipRanges := utils.GenerateIPRange(ipnet)

	ipChan := make(chan net.IP, len(ipRanges))
	for _, ip := range ipRanges {
		ipChan <- ip
	}
	close(ipChan)

	workerSem := make(chan struct{}, d.workers)

	for ip := range ipChan {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case workerSem <- struct{}{}:
			wg.Add(1)
			go func(ip net.IP) {
				defer wg.Done()
				defer func() { <-workerSem }()

				host, err := d.scanHost(ctx, ip, options)
				if err == nil && host != nil {
					mu.Lock()
					hosts = append(hosts, *host)
					mu.Unlock()
				}
			}(ip)
		}
	}

	wg.Wait()
	return hosts, nil
}

func (d *TCPHostDiscoverer) scanHost(ctx context.Context, ip net.IP, options ScanOptions) (*HostInfo, error) {
	for _, port := range d.portList {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip.String(), port), d.timeout)
		if err == nil {
			conn.Close()

			hostname := ""
			if options.ResolveHostname {
				hostnames, err := net.LookupAddr(ip.String())
				if err == nil && len(hostnames) > 0 {
					hostname = strings.TrimSuffix(hostnames[0], ".")
				}
			}

			host := &HostInfo{
				IP:       ip,
				Hostname: hostname,
				Status:   "up",
				LastSeen: time.Now(),
			}

			return host, nil
		}
	}

	return nil, errors.New("主机不可达")
}

// ARPHostDiscoverer 基于ARP的主机发现实现
// 注意：ARP扫描仅适用于本地网络

type ARPHostDiscoverer struct {
	interfaceName string
	timeout       time.Duration
}

func NewARPHostDiscoverer(interfaceName string, timeout time.Duration) *ARPHostDiscoverer {
	return &ARPHostDiscoverer{
		interfaceName: interfaceName,
		timeout:       timeout,
	}
}

func (d *ARPHostDiscoverer) Discover(ctx context.Context, target string, options ScanOptions) ([]HostInfo, error) {
	return []HostInfo{}, nil
}
