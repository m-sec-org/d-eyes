package assets

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"time"

	"github.com/m-sec-org/d-eyes/internal/assets/utils"
	"github.com/m-sec-org/d-eyes/internal/progress"
)

// BasicHostDetector 通过尝试TCP连接实现的通用主机发现器
type BasicHostDetector struct {
	timeout  time.Duration
	ports    []int
	workers  int
	progress *progress.Manager
}

// NewBasicHostDetector 创建基础主机发现器
func NewBasicHostDetector(timeout time.Duration, ports []int) *BasicHostDetector {
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	validPorts := make([]int, 0, len(ports))
	for _, port := range ports {
		if utils.IsValidPort(port) {
			validPorts = append(validPorts, port)
		}
	}
	if len(validPorts) == 0 {
		validPorts = []int{80, 443, 22}
	}
	return &BasicHostDetector{
		timeout: timeout,
		ports:   validPorts,
		workers: 32,
	}
}

// SetProgress 设置进度管理器
func (d *BasicHostDetector) SetProgress(p *progress.Manager) {
	d.progress = p
}

// DetectHosts 尝试通过TCP连接判断主机是否存活
func (d *BasicHostDetector) DetectHosts(target string) ([]net.IP, error) {
	return d.DetectHostsWithContext(context.Background(), target)
}

// DetectHostsWithContext 支持上下文取消的主机发现
func (d *BasicHostDetector) DetectHostsWithContext(ctx context.Context, target string) ([]net.IP, error) {
	ips, err := utils.GetIPsFromTarget(target)
	if err != nil {
		return nil, err
	}

	if d.progress != nil {
		d.progress.StartStage(progress.StageDiscoverHosts, len(ips), fmt.Sprintf("目标 %s", target))
	}

	result := make([]net.IP, 0, len(ips))
	seen := make(map[string]struct{})
	var mu sync.Mutex
	workerCount := d.workers
	if workerCount <= 0 {
		workerCount = 8
	}
	sem := make(chan struct{}, workerCount)
	var wg sync.WaitGroup

	for _, ip := range ips {
		if ip == nil {
			continue
		}
		ipCopy := ip
		key := ipCopy.String()
		wg.Add(1)
		go func(ip net.IP, key string) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-sem }()

			reachable := d.isReachable(ctx, ip)
			if reachable {
				mu.Lock()
				if _, ok := seen[key]; !ok {
					seen[key] = struct{}{}
					result = append(result, ip)
				}
				mu.Unlock()
			}
			if d.progress != nil {
				status := "不可达"
				if reachable {
					status = "可达"
				}
				d.progress.Add(progress.StageDiscoverHosts, 1, fmt.Sprintf("%s %s", ip.String(), status))
			}
		}(ipCopy, key)
	}

	wg.Wait()
	if err := ctx.Err(); err != nil {
		return result, err
	}
	return result, nil
}

func (d *BasicHostDetector) isReachable(ctx context.Context, ip net.IP) bool {
	timeout := d.timeout
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	for _, port := range d.ports {
		addr := formatAddress(ip, port)
		dialer := &net.Dialer{Timeout: timeout}
		conn, err := dialer.DialContext(ctx, "tcp", addr)
		if err == nil {
			_ = conn.Close()
			return true
		}
		if ctx.Err() != nil {
			return false
		}
	}
	return false
}

func formatAddress(ip net.IP, port int) string {
	if ip.To4() == nil {
		return fmt.Sprintf("[%s]:%d", ip.String(), port)
	}
	return fmt.Sprintf("%s:%d", ip.String(), port)
}

// CompositeHostDiscoverer 组合多个主机发现器
type CompositeHostDiscoverer struct {
	discoverers []HostDetector
	progress    *progress.Manager
}

// NewCompositeHostDiscoverer 创建组合主机发现器
func NewCompositeHostDiscoverer(discoverers ...HostDetector) *CompositeHostDiscoverer {
	return &CompositeHostDiscoverer{
		discoverers: discoverers,
	}
}

// SetProgress 向内部探测器传播进度管理器
func (d *CompositeHostDiscoverer) SetProgress(p *progress.Manager) {
	d.progress = p
	for _, discoverer := range d.discoverers {
		if setter, ok := discoverer.(interface{ SetProgress(*progress.Manager) }); ok {
			setter.SetProgress(p)
		}
	}
}

// DetectHosts 实现HostDetector接口的DetectHosts方法
func (d *CompositeHostDiscoverer) DetectHosts(target string) ([]net.IP, error) {
	return d.DetectHostsWithContext(context.Background(), target)
}

// DetectHostsWithContext 实现支持上下文的主机发现
func (d *CompositeHostDiscoverer) DetectHostsWithContext(ctx context.Context, target string) ([]net.IP, error) {
	hosts, err := d.discover(ctx, target)
	if err != nil {
		return nil, err
	}
	ips := make([]net.IP, 0, len(hosts))
	for _, host := range hosts {
		ips = append(ips, host.IP)
	}
	return ips, nil
}

// discover 内部方法用于执行主机发现
func (d *CompositeHostDiscoverer) discover(ctx context.Context, target string) ([]HostInfo, error) {
	var (
		allHosts []HostInfo
		hostMap  = make(map[string]HostInfo)
		errSeen  error
	)

	for _, discoverer := range d.discoverers {
		if discoverer == nil {
			continue
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		var (
			ips []net.IP
			err error
		)
		if ctxAware, ok := discoverer.(ContextAwareHostDetector); ok {
			ips, err = ctxAware.DetectHostsWithContext(ctx, target)
		} else {
			ips, err = discoverer.DetectHosts(target)
		}
		if err != nil {
			errSeen = err
			continue
		}
		for _, ip := range ips {
			if ip == nil {
				continue
			}
			key := ip.String()
			if _, exists := hostMap[key]; exists {
				continue
			}
			hostMap[key] = HostInfo{
				IP:       ip,
				Status:   "up",
				LastSeen: time.Now(),
			}
		}
	}

	for _, host := range hostMap {
		allHosts = append(allHosts, host)
	}

	if len(allHosts) == 0 && errSeen != nil {
		return nil, errSeen
	}

	return allHosts, nil
}

// IsRootRequired 检查是否需要管理员/root权限
func IsRootRequired() bool {
	if runtime.GOOS == "windows" {
		cmd := exec.Command("net", "session")
		err := cmd.Run()
		return err != nil
	}
	return os.Geteuid() != 0
}
