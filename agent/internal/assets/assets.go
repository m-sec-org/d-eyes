package assets

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/urfave/cli/v2"

	"github.com/m-sec-org/d-eyes/agent/internal/assets/utils"
	"github.com/m-sec-org/d-eyes/agent/pkg/color"
)

const defaultFastScanPorts = "80,443,22,3389,8080,8443,3306,5432,1433,27017"

var assetsScannerFactory = CreateScannerFromOptions

var commonAssetFlags = []cli.Flag{
	&cli.StringFlag{
		Name:    "format",
		Aliases: []string{"f"},
		Value:   "table",
		Usage:   "输出格式: table, json, csv, text",
	},
	&cli.StringFlag{
		Name:    "output",
		Aliases: []string{"o"},
		Value:   "",
		Usage:   "输出文件路径，默认为标准输出",
	},
	&cli.BoolFlag{
		Name:    "verbose",
		Aliases: []string{"v"},
		Value:   false,
		Usage:   "显示详细信息",
	},
	&cli.BoolFlag{
		Name:  "color",
		Value: true,
		Usage: "使用彩色输出",
	},
	&cli.BoolFlag{
		Name:    "debug",
		Aliases: []string{"d"},
		Usage:   "输出调试详情信息",
		Value:   false,
	},
	&cli.StringFlag{
		Name:    "interface",
		Aliases: []string{"i"},
		Value:   "",
		Usage:   "指定网络接口",
	},
	&cli.StringFlag{
		Name:  "discovery",
		Value: "",
		Usage: "主机发现方法: icmp, tcp, arp, mixed",
	},
	&cli.StringFlag{
		Name:  "scan-method",
		Value: "",
		Usage: "端口扫描方法: tcp, syn, udp",
	},
	&cli.StringFlag{
		Name:    "ports",
		Aliases: []string{"p"},
		Value:   "",
		Usage:   "端口范围，如: 80,443,8080-8090 或 'common'",
	},
	&cli.IntFlag{
		Name:  "timeout",
		Value: 2,
		Usage: "连接超时时间（秒）",
	},
	&cli.IntFlag{
		Name:  "rate",
		Value: 0,
		Usage: "每秒最大发起的端口探测次数 (0 表示自动)",
	},
	&cli.BoolFlag{
		Name:  "local",
		Value: false,
		Usage: "本地网络扫描（启用ARP扫描）",
	},
	&cli.BoolFlag{
		Name:  "arp",
		Value: false,
		Usage: "使用ARP扫描（适用于本地网络）",
	},
	&cli.BoolFlag{
		Name:  "hosts-only",
		Value: false,
		Usage: "仅执行主机发现，不进行端口扫描",
	},
	&cli.BoolFlag{
		Name:  "service-detect",
		Value: false,
		Usage: "启用服务指纹识别",
	},
	&cli.BoolFlag{
		Name:  "os-detect",
		Value: false,
		Usage: "启用操作系统指纹识别",
	},
	&cli.BoolFlag{
		Name:  "resolve",
		Value: false,
		Usage: "解析主机名",
	},
	&cli.BoolFlag{
		Name:  "banner",
		Value: false,
		Usage: "获取服务Banner信息",
	},
}

func cloneAssetFlags() []cli.Flag {
	return append([]cli.Flag(nil), commonAssetFlags...)
}

// SetAssetsScannerFactory 设置全局扫描器工厂（主要用于测试）
func SetAssetsScannerFactory(factory func(ScanOptions) *AssetScanner) {
	if factory == nil {
		assetsScannerFactory = CreateScannerFromOptions
		return
	}
	assetsScannerFactory = factory
}

// NewAssetsCommand 创建资产探测命令
func NewAssetsCommand() *cli.Command {
	return &cli.Command{
		Name:    "assets",
		Aliases: []string{"as"},
		Usage:   "资产探测模块 - 用于发现网络资产和服务",
		Description: `资产探测模块用于发现网络中的活跃主机、开放端口和运行服务。
支持多种扫描方式，包括ICMP、TCP、ARP等主机发现方法，
以及TCP全连接、SYN半开等端口扫描技术。`,
		Flags: cloneAssetFlags(),
		Subcommands: []*cli.Command{
			newScanCommand(),
			newDiscoverCommand(),
			newInfoCommand(),
			newFastScanCommand(),
			newLocalScanCommand(),
			newNetworkScanCommand(),
		},
		Action: func(c *cli.Context) error {
			showHelp()
			return nil
		},
	}
}

// newScanCommand 创建全面扫描命令
func newScanCommand() *cli.Command {
	flags := cloneAssetFlags()
	return &cli.Command{
		Name:  "scan",
		Usage: "全面扫描目标资产",
		Description: `对指定目标执行全面的资产扫描，包括主机发现和端口扫描。
目标可以是单个IP地址、域名或CIDR网段。

示例:
  assets scan 192.168.1.1          # 扫描单个IP
  assets scan example.com          # 扫描域名
  assets scan 192.168.1.0/24       # 扫描整个网段
  assets scan 192.168.1.0/24 -p 80,443,8080-8090  # 指定端口范围`,
		ArgsUsage: "[target]",
		Flags:     flags,
		Action: func(c *cli.Context) error {
			if c.Args().Len() != 1 {
				return fmt.Errorf("必须提供一个目标参数")
			}
			return runScan(c)
		},
	}
}

// newDiscoverCommand 创建主机发现命令
func newDiscoverCommand() *cli.Command {
	flags := cloneAssetFlags()
	return &cli.Command{
		Name:  "discover",
		Usage: "发现网络中的活跃主机",
		Description: `仅执行主机发现，不进行端口扫描。
目标可以是单个IP地址、域名或CIDR网段。

示例:
  assets discover 192.168.1.0/24   # 发现网段中的活跃主机
  assets discover 192.168.1.0/24 --discovery=arp  # 使用ARP扫描（本地网络）
  assets discover 192.168.1.0/24 --resolve  # 解析主机名`,
		ArgsUsage: "[target]",
		Flags:     flags,
		Action: func(c *cli.Context) error {
			if c.Args().Len() != 1 {
				return fmt.Errorf("必须提供一个目标参数")
			}
			return runDiscover(c)
		},
	}
}

// newInfoCommand 创建资产信息命令
func newInfoCommand() *cli.Command {
	flags := cloneAssetFlags()
	return &cli.Command{
		Name:  "info",
		Usage: "获取目标主机详细信息",
		Description: `对单个目标主机进行详细信息收集，包括开放端口、服务识别等。

示例:
  assets info 192.168.1.1          # 获取单个主机的详细信息
  assets info example.com --banner  # 获取并显示服务Banner信息
  assets info 192.168.1.1 -p 'common'  # 扫描常用端口`,
		ArgsUsage: "[target]",
		Flags:     flags,
		Action: func(c *cli.Context) error {
			if c.Args().Len() != 1 {
				return fmt.Errorf("必须提供一个目标参数")
			}
			return runInfo(c)
		},
	}
}

// newFastScanCommand 创建快速扫描命令
func newFastScanCommand() *cli.Command {
	flags := cloneAssetFlags()
	return &cli.Command{
		Name:  "fast",
		Usage: "快速扫描目标（仅扫描常用端口）",
		Description: `对目标执行快速扫描，仅扫描最常用的端口。
适用于快速了解目标的基本服务情况。

示例:
  assets fast 192.168.1.0/24       # 快速扫描网段
  assets fast example.com          # 快速扫描域名`,
		ArgsUsage: "[target]",
		Flags:     flags,
		Action: func(c *cli.Context) error {
			if c.Args().Len() != 1 {
				return fmt.Errorf("必须提供一个目标参数")
			}
			return runFastScan(c)
		},
	}
}

// newNetworkScanCommand 创建网络扫描命令
func newNetworkScanCommand() *cli.Command {
	flags := cloneAssetFlags()
	return &cli.Command{
		Name:  "network",
		Usage: "扫描整个网络（自动转换为C类网段）",
		Description: `扫描整个网络，自动将IP地址转换为C类网段（/24）。

示例:
  assets network 192.168.1.1       # 扫描192.168.1.0/24网段
  assets network 192.168.1.0/24    # 直接扫描指定网段`,
		ArgsUsage: "[network]",
		Flags:     flags,
		Action: func(c *cli.Context) error {
			if c.Args().Len() != 1 {
				return fmt.Errorf("必须提供一个网络参数")
			}
			return runNetworkScan(c)
		},
	}
}

// newLocalScanCommand 创建本地网络扫描命令
func newLocalScanCommand() *cli.Command {
	flags := cloneAssetFlags()
	flags = append(flags,
		&cli.BoolFlag{
			Name:  "include-loopback",
			Usage: "包含回环接口",
			Value: false,
		},
		&cli.IntFlag{
			Name:  "limit",
			Usage: "最多扫描的网段数量 (0 表示不限制)",
			Value: 0,
		},
	)
	return &cli.Command{
		Name:  "local",
		Usage: "基于本机网络信息自动扫描局域网",
		Description: `自动枚举本机所有活动网络接口并扫描对应的局域网网段。

示例:
  assets local                # 扫描所有活动接口所属网段
  assets local --limit=1      # 仅扫描第一个探测到的网段`,
		Flags: flags,
		Action: func(c *cli.Context) error {
			return runLocalScan(c)
		},
	}
}

// 运行扫描命令
func runScan(c *cli.Context) error {
	target := c.Args().First()
	runner := NewAssetsRunner(buildConfigFromCLI(c))
	runner.SetScannerFactory(assetsScannerFactory)

	options := buildScanOptionsFromCLI(c)
	options.HostDiscoveryOnly = false
	normalizeScanOptions(&options)

	if err := ValidateScannerOptions(options); err != nil {
		return fmt.Errorf("扫描选项错误: %v", err)
	}

	ctx, cancel := createContextWithSignal(runner.Config.Verbose)
	defer cancel()

	return runner.Execute(ctx, ScanRequest{
		Target:   target,
		ScanType: "comprehensive",
		Options:  options,
	})
}

// 运行主机发现命令
func runDiscover(c *cli.Context) error {
	target := c.Args().First()

	runner := NewAssetsRunner(buildConfigFromCLI(c))
	runner.SetScannerFactory(assetsScannerFactory)

	options := buildScanOptionsFromCLI(c)
	options.HostDiscoveryOnly = true
	normalizeScanOptions(&options)

	if err := ValidateScannerOptions(options); err != nil {
		return fmt.Errorf("扫描选项错误: %v", err)
	}

	ctx, cancel := createContextWithSignal(runner.Config.Verbose)
	defer cancel()

	return runner.Execute(ctx, ScanRequest{
		Target:   target,
		ScanType: "host_discovery",
		Options:  options,
	})
}

// 运行信息收集命令
func runInfo(c *cli.Context) error {
	target := c.Args().First()

	runner := NewAssetsRunner(buildConfigFromCLI(c))
	runner.SetScannerFactory(assetsScannerFactory)

	options := buildScanOptionsFromCLI(c)
	options.ResolveHostname = true
	options.GetBanner = true
	options.HostDiscoveryOnly = false
	normalizeScanOptions(&options)

	if err := ValidateScannerOptions(options); err != nil {
		return fmt.Errorf("扫描选项错误: %v", err)
	}

	ctx, cancel := createContextWithSignal(runner.Config.Verbose)
	defer cancel()

	return runner.Execute(ctx, ScanRequest{
		Target:   target,
		ScanType: "host_info",
		Options:  options,
	})
}

// 运行快速扫描命令
func runFastScan(c *cli.Context) error {
	target := c.Args().First()

	runner := NewAssetsRunner(buildConfigFromCLI(c))
	runner.SetScannerFactory(assetsScannerFactory)

	options := buildScanOptionsFromCLI(c)
	options.Ports = runner.Config.FastScanPorts
	options.HostDiscoveryOnly = false
	normalizeScanOptions(&options)

	if err := ValidateScannerOptions(options); err != nil {
		return fmt.Errorf("扫描选项错误: %v", err)
	}

	ctx, cancel := createContextWithSignal(runner.Config.Verbose)
	defer cancel()

	return runner.Execute(ctx, ScanRequest{
		Target:   target,
		ScanType: "fast",
		Options:  options,
	})
}

// 运行网络扫描命令
func runNetworkScan(c *cli.Context) error {
	target := c.Args().First()

	runner := NewAssetsRunner(buildConfigFromCLI(c))
	runner.SetScannerFactory(assetsScannerFactory)

	network := utils.ConvertToNetwork(target, 24)
	if runner.Config.Verbose {
		fmt.Printf("扫描网络: %s (自动转换)\n", network)
	}

	options := buildScanOptionsFromCLI(c)
	options.Ports = runner.Config.FastScanPorts
	options.HostDiscoveryOnly = false
	options.LocalScan = true
	normalizeScanOptions(&options)

	if err := ValidateScannerOptions(options); err != nil {
		return fmt.Errorf("扫描选项错误: %v", err)
	}

	ctx, cancel := createContextWithSignal(runner.Config.Verbose)
	defer cancel()

	return runner.Execute(ctx, ScanRequest{
		Target:   network,
		ScanType: "network",
		Options:  options,
	})
}

var discoverLocalNetworksFn = DiscoverLocalNetworks

// SetLocalNetworkDiscoverer 测试时替换本地网络发现函数
func SetLocalNetworkDiscoverer(fn func(bool) ([]LocalNetwork, error)) {
	if fn == nil {
		discoverLocalNetworksFn = DiscoverLocalNetworks
		return
	}
	discoverLocalNetworksFn = fn
}

// 运行本地网络扫描
func runLocalScan(c *cli.Context) error {
	runner := NewAssetsRunner(buildConfigFromCLI(c))
	runner.SetScannerFactory(assetsScannerFactory)

	options := buildScanOptionsFromCLI(c)
	options.LocalScan = true
	options.HostDiscoveryOnly = false
	normalizeScanOptions(&options)

	includeLoopback := c.Bool("include-loopback")
	limit := c.Int("limit")

	networks, err := discoverLocalNetworksFn(includeLoopback)
	if err != nil {
		return err
	}
	if len(networks) == 0 {
		return fmt.Errorf("未发现可用的本地网段")
	}
	if limit > 0 && limit < len(networks) {
		networks = networks[:limit]
	}

	requests := make([]ScanRequest, 0, len(networks))
	for _, nw := range networks {
		if runner.Config.Verbose {
			fmt.Printf("扫描本地网段: %s (%s)\n", nw.CIDR, nw.Interface)
		}
		opts := options
		opts.Interface = nw.Interface
		req := ScanRequest{
			Target:   nw.CIDR,
			ScanType: "local_network",
			Options:  opts,
		}
		requests = append(requests, req)
	}

	ctx, cancel := createContextWithSignal(runner.Config.Verbose)
	defer cancel()

	extra := map[string]interface{}{
		"networks_scanned": FormatLocalNetworks(networks),
	}

	return runner.ExecuteAggregate(ctx, requests, extra)
}

func normalizeScanOptions(options *ScanOptions) {
	if options == nil {
		return
	}
	discovery := strings.ToLower(options.DiscoveryMethod)
	if options.ArpScan {
		discovery = "arp"
		options.LocalScan = true
	}
	if options.LocalScan && discovery == "" {
		discovery = "mixed"
	}
	options.DiscoveryMethod = discovery
}

// isValidIPAddress 检查是否为有效的IP地址
func isValidIPAddress(ip string) bool {
	return net.ParseIP(ip) != nil
}

// isValidCIDR 检查是否为有效的CIDR表示
func isValidCIDR(cidr string) bool {
	_, _, err := net.ParseCIDR(cidr)
	return err == nil
}

// 创建支持信号中断的上下文
func createContextWithSignal(verbose bool) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())

	// 监听中断信号
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-c
		if verbose {
			fmt.Println("\n扫描被用户中断...")
		}
		cancel()
	}()

	return ctx, cancel
}

func warnPrivilegeRequirement(options ScanOptions, _ bool) {
	method := strings.ToLower(options.ScanMethod)
	if method == "syn" && !isPrivilegedUser() {
		fmt.Println(color.Yellow.Sprintf("提示: SYN 扫描需要管理员/Root 权限，当前会回退为 TCP connect 扫描。"))
	}
	if method == "udp" && !isPrivilegedUser() {
		fmt.Println(color.Yellow.Sprintf("提示: UDP 扫描可能需要更高权限以发送原始报文。"))
	}
	if options.RateLimit > 0 && options.RateLimit < 10 {
		fmt.Println(color.Yellow.Sprintf("提示: 当前速率限制为每秒 %d 个探测，可能导致扫描时间较长。", options.RateLimit))
	}
}

// 显示帮助信息
func showHelp() {
	fmt.Println("资产探测模块使用指南:")
	fmt.Println("  assets [命令] [参数] [选项]")
	fmt.Println("")
	fmt.Println("命令:")
	fmt.Println("  scan       全面扫描目标资产")
	fmt.Println("  discover   发现网络中的活跃主机")
	fmt.Println("  info       获取目标主机详细信息")
	fmt.Println("  fast       快速扫描目标（仅扫描常用端口）")
	fmt.Println("  network    扫描整个网络（自动转换为C类网段）")
	fmt.Println("")
	fmt.Println("示例:")
	fmt.Println("  assets scan 192.168.1.1          # 扫描单个IP")
	fmt.Println("  assets discover 192.168.1.0/24   # 发现网段中的活跃主机")
	fmt.Println("  assets info 192.168.1.1          # 获取单个主机的详细信息")
	fmt.Println("  assets fast 192.168.1.0/24       # 快速扫描网段")
	fmt.Println("  assets network 192.168.1.1       # 扫描192.168.1.0/24网段")
	fmt.Println("")
	fmt.Println("使用 'assets [命令] --help' 查看命令的详细选项")
}
