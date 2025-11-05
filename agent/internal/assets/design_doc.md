# D-Eyes 资产探测模块详细设计方案

## 1. 模块概述

资产探测模块是D-Eyes工具的核心功能模块之一，主要用于发现网络环境中的主机资产，支持给定目标范围或自动探测周边网络，帮助用户全面了解网络资产情况。该模块能够扫描内网和外网主机，探测主机的可达性、开放端口、运行服务及其版本信息等。

### 1.1 主要功能点

- **主机发现**：基于ICMP、ARP、TCP SYN等多种方式探测主机存活状态
- **端口扫描**：快速扫描目标主机的开放端口，支持自定义端口范围
- **服务识别**：识别开放端口上运行的服务及其版本信息
- **操作系统指纹识别**：通过TTL、窗口大小、Banner等多维信息推断目标主机的操作系统类型
- **域名解析**：支持域名到IP的解析和反向解析
- **网络自动发现**：自动识别本地网络并探测周边主机
- **多格式报告输出**：支持JSON、CSV、TEXT等多种格式的报告生成
- **并发扫描**：支持可配置的并发线程数，提高扫描效率

## 2. 架构设计

### 2.1 模块结构

```
internal/
├── assets/                  # 资产探测模块
│   ├── base.go              # 基础定义（接口和数据结构）
│   ├── scanner.go           # 扫描器实现
│   ├── port_scanner.go      # 端口扫描器
│   ├── host_detector.go     # 主机探测器
│   ├── service_detector.go  # 服务识别器
│   ├── os_detector.go       # 操作系统识别器
│   ├── network_discovery.go # 网络发现器
│   ├── reporter/            # 报告生成器
│   │   ├── json_reporter.go # JSON格式报告
│   │   ├── csv_reporter.go  # CSV格式报告
│   │   └── text_reporter.go # 文本格式报告
│   ├── utils/               # 工具函数
│   │   ├── ip_utils.go      # IP地址处理
│   │   ├── port_utils.go    # 端口处理
│   │   └── scan_utils.go    # 扫描相关工具
│   ├── fingerprints/        # 指纹规则
│   │   ├── services.yaml    # 常用服务指纹
│   │   └── os.yaml          # 操作系统指纹
│   └── factory.go           # 工厂类
└── assets.go                # 命令行接口
```

### 2.2 核心接口设计

#### 2.2.1 扫描器接口（Scanner）

```go
// Scanner 探测器接口
\n... (rest of document unchanged, but include service/os fingerprint info under respective sections) ...
```
