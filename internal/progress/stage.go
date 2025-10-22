package progress

// Stage 表示扫描阶段
type Stage string

const (
	StageDiscoverHosts   Stage = "discover_hosts"
	StagePortScan        Stage = "port_scan"
	StageServiceDetect   Stage = "service_detect"
	StageBenchmark       Stage = "benchmark"
	StageBenchmarkChecks Stage = "benchmark_checks"
)

func stageLabel(stage Stage) string {
	switch stage {
	case StageDiscoverHosts:
		return "主机发现"
	case StagePortScan:
		return "端口扫描"
	case StageServiceDetect:
		return "服务识别"
	case StageBenchmark:
		return "加载检查器"
	case StageBenchmarkChecks:
		return "执行检查"
	default:
		return string(stage)
	}
}
