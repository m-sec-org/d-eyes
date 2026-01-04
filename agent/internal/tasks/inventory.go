package tasks

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/m-sec-org/d-eyes/agent/internal/assets"
	"github.com/m-sec-org/d-eyes/agent/internal/debugger"
	"github.com/m-sec-org/d-eyes/agent/internal/progress"
	"github.com/m-sec-org/d-eyes/agent/internal/tasks/taskcache"
	"github.com/m-sec-org/d-eyes/agent/pkg/reporting"
)

const (
	inventoryCacheNamespace       = "inventory.scan"
	inventoryTargetCacheNamespace = "inventory.scan.targets"
)

var inventoryCacheTTL = 6 * time.Hour

type debugProgressReporter struct {
	emitter *debugger.Emitter
}

func (r debugProgressReporter) Stage(stage progress.Stage, total int, description string) {
	if r.emitter == nil {
		return
	}
	r.emitter.PhaseStart(string(stage), description, fmt.Sprintf("total=%d", total))
}

func (r debugProgressReporter) Update(stage progress.Stage, current int, total int, detail string) {
	if r.emitter == nil {
		return
	}
	r.emitter.Progress(string(stage), current, total, detail)
}

func (r debugProgressReporter) Debug(message string) {
	if r.emitter == nil {
		return
	}
	r.emitter.Notice("inventory", message)
}

func (r debugProgressReporter) Finish() {}

type inventoryExecutor interface {
	ScanTarget(ctx context.Context, target string, opts assets.ScanOptions, req TaskRequest) (inventoryReport, error)
}

type inventoryRunner struct {
	executor inventoryExecutor
}

func InventoryRunner() TaskRunner {
	return InventoryRunnerWithExecutor(nil)
}

func InventoryRunnerWithExecutor(exec inventoryExecutor) TaskRunner {
	if exec == nil {
		exec = defaultInventoryExecutor{}
	}
	return &inventoryRunner{executor: exec}
}

func (r *inventoryRunner) Run(ctx context.Context, req TaskRequest) (TaskResult, error) {
	targets := parseTargets(req)
	if len(targets) == 0 {
		return TaskResult{}, errors.New("inventory 任务需要至少一个 --targets 目标")
	}

	profile := strings.ToLower(req.Profile)
	if profile == "" {
		profile = "fast"
	}
	if req.Debugger != nil {
		req.Debugger.PhaseStart("inventory", "targets", fmt.Sprintf("count=%d profile=%s", len(targets), profile))
	}
	baseOptions := buildInventoryOptions(profile, req.Flags)
	if req.Debugger != nil {
		if baseOptions.EnableServiceDetect {
			req.Debugger.Notice("inventory", "已启用服务识别")
		}
		if baseOptions.EnableOSDetect {
			req.Debugger.Notice("inventory", "已启用系统识别")
		}
	}

	results := make([]inventoryReport, 0, len(targets))
	outputs := make([]reporting.OutputRecord, 0, len(targets)+1)
	riskTotals := make(map[string]int)
	resultMetadata := map[string]string{
		"profile":      profile,
		"target_count": fmt.Sprintf("%d", len(targets)),
		"targets":      strings.Join(targets, ","),
		"scan_scope":   profile,
	}
	cacheKey := inventoryCacheKey(profile, targets, baseOptions, req.Flags)
	if cached, ok, err := restoreInventoryFromCache(req, cacheKey); err == nil && ok {
		return cached, nil
	} else if err != nil {
		resultMetadata["cache.restore_error"] = err.Error()
	}

	exec := r.executor
	for idx, target := range targets {
		select {
		case <-ctx.Done():
			if req.Debugger != nil {
				req.Debugger.Notice("inventory", "任务被取消")
			}
			return TaskResult{Outputs: outputs, Risks: riskTotals, Notes: []string{"任务被取消"}}, ctx.Err()
		default:
		}
		if req.Debugger != nil {
			req.Debugger.PhaseStart("inventory.target", target, fmt.Sprintf("%d/%d", idx+1, len(targets)))
		}
		report, err := exec.ScanTarget(ctx, target, baseOptions, req)
		if err != nil {
			if req.Debugger != nil {
				req.Debugger.Error("inventory.target", fmt.Sprintf("%s: %v", target, err))
			}
			return TaskResult{}, err
		}
		results = append(results, report)
		outputs = append(outputs, report.OutputRecord)
		accumulateRisk(riskTotals, report.Risks)
		cacheInventoryTarget(cacheKey, report)
		if req.Debugger != nil {
			req.Debugger.Artifact("inventory", report.OutputRecord.Path)
			req.Debugger.PhaseEnd("inventory.target", target)
			req.Debugger.Progress("inventory", idx+1, len(targets), target)
		}
	}

	if summaryRecord, summaryMeta, err := writeInventorySummary(req, results, riskTotals, targets, cacheKey, profile); err == nil && summaryRecord.Path != "" {
		outputs = append(outputs, summaryRecord)
		for k, v := range summaryMeta {
			resultMetadata[k] = v
		}
		if req.Debugger != nil {
			req.Debugger.Artifact("inventory", summaryRecord.Path)
		}
	}

	if req.Debugger != nil {
		req.Debugger.PhaseEnd("inventory", "complete")
	}
	return TaskResult{
		Outputs:  outputs,
		Risks:    riskTotals,
		Metadata: resultMetadata,
	}, nil
}

type inventoryReport struct {
	Target       string
	Hosts        []assets.HostInfo
	Ports        []assets.PortInfo
	OutputRecord reporting.OutputRecord
	Risks        map[string]int
	Path         string
}

type defaultInventoryExecutor struct{}

func (defaultInventoryExecutor) ScanTarget(ctx context.Context, target string, opts assets.ScanOptions, req TaskRequest) (inventoryReport, error) {
	scanner := assets.CreateScannerFromOptions(opts)
	if scanner == nil {
		return inventoryReport{}, fmt.Errorf("无法创建扫描器")
	}
	var reporter progress.Reporter = progress.NullReporter{}
	if req.Debugger != nil {
		reporter = debugProgressReporter{emitter: req.Debugger}
	}
	manager := progress.NewManager(reporter, 500*time.Millisecond, opts.Debug || req.Debug)
	scanner.SetProgress(manager)
	defer manager.Finish()

	result, err := scanner.Scan(ctx, target)
	if err != nil {
		return inventoryReport{}, err
	}

	report := struct {
		Target     string            `json:"target"`
		Profile    string            `json:"profile"`
		Hosts      []inventoryHost   `json:"hosts"`
		Ports      []inventoryPort   `json:"ports"`
		StartedAt  time.Time         `json:"started_at"`
		FinishedAt time.Time         `json:"finished_at"`
		Statistics map[string]int    `json:"statistics"`
		Options    map[string]any    `json:"options"`
		RawHosts   []assets.HostInfo `json:"-"`
		RawPorts   []assets.PortInfo `json:"-"`
	}{Target: target, Profile: req.Profile, StartedAt: result.StartTime, FinishedAt: result.EndTime}

	report.Options = optionsToMap(opts)
	report.Statistics = map[string]int{
		"hosts": len(result.Hosts),
		"ports": len(result.Ports),
	}

	report.Hosts = make([]inventoryHost, 0, len(result.Hosts))
	for _, h := range result.Hosts {
		report.Hosts = append(report.Hosts, inventoryHost{
			IP:         h.IP.String(),
			Hostname:   h.Hostname,
			Status:     h.Status,
			LastSeen:   h.LastSeen,
			OS:         h.OSType,
			Confidence: h.OSConfidence,
		})
	}
	report.Ports = make([]inventoryPort, 0, len(result.Ports))
	for _, p := range result.Ports {
		host := p.IP.String()
		report.Ports = append(report.Ports, inventoryPort{
			IP:         host,
			Port:       p.Port,
			State:      p.State,
			Service:    p.Service,
			Banner:     p.Banner,
			Protocol:   p.Protocol,
			Confidence: p.Confidence,
		})
	}

	fileName := sanitizeFileComponent(target)
	file, path, err := req.Manager.CreateFile("inventory", fmt.Sprintf("%s-%s", req.Name, fileName), "json")
	if err != nil {
		return inventoryReport{}, err
	}
	defer file.Close()
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(report); err != nil {
		return inventoryReport{}, err
	}

	risks := evaluateInventoryRisk(result.Ports)
	return inventoryReport{
		Target: target,
		Hosts:  result.Hosts,
		Ports:  result.Ports,
		OutputRecord: reporting.OutputRecord{
			Label: fmt.Sprintf("资产扫描：%s", target),
			Path:  path,
		},
		Risks: risks,
		Path:  path,
	}, nil
}

func buildInventoryOptions(profile string, flags map[string]any) assets.ScanOptions {
	options := assets.ScanOptions{
		DiscoveryMethod:     "mixed",
		ScanMethod:          "tcp",
		Ports:               fastPorts,
		Timeout:             3,
		RateLimit:           0,
		LocalScan:           false,
		HostDiscoveryOnly:   false,
		ResolveHostname:     getBoolFlag(flags, "resolve"),
		GetBanner:           getBoolFlag(flags, "service-detect"),
		EnableServiceDetect: getBoolFlag(flags, "service-detect"),
		EnableOSDetect:      getBoolFlag(flags, "os-detect"),
		Verbose:             false,
		Debug:               false,
		Concurrency:         50,
	}

	switch profile {
	case "fast":
		options.Ports = fastPorts
		options.Timeout = 2
		options.RateLimit = 1000
	case "deep":
		options.Ports = "1-65535"
		options.Timeout = 5
		options.RateLimit = 200
		options.EnableServiceDetect = true
		options.EnableOSDetect = true
	case "stealth":
		options.Ports = fastPorts
		options.Timeout = 4
		options.RateLimit = 50
		options.HostDiscoveryOnly = false
		options.EnableServiceDetect = false
		options.EnableOSDetect = false
		options.GetBanner = false
	default:
	}

	if ports := getStringFlag(flags, "ports", ""); ports != "" {
		options.Ports = ports
	}

	return options
}

func writeInventorySummary(req TaskRequest, reports []inventoryReport, risks map[string]int, targets []string, cacheKey, profile string) (reporting.OutputRecord, map[string]string, error) {
	file, path, err := req.Manager.CreateFile("inventory", req.Name+"-summary", "json")
	if err != nil {
		return reporting.OutputRecord{}, nil, err
	}
	defer file.Close()

	totalHosts := 0
	totalPorts := 0
	targetSummaries := make([]struct {
		Target string `json:"target"`
		Hosts  int    `json:"hosts"`
		Ports  int    `json:"ports"`
	}, 0, len(reports))

	for _, rep := range reports {
		targetSummaries = append(targetSummaries, struct {
			Target string `json:"target"`
			Hosts  int    `json:"hosts"`
			Ports  int    `json:"ports"`
		}{
			Target: rep.Target,
			Hosts:  len(rep.Hosts),
			Ports:  len(rep.Ports),
		})
		totalHosts += len(rep.Hosts)
		totalPorts += len(rep.Ports)
	}
	sort.Slice(targetSummaries, func(i, j int) bool { return targetSummaries[i].Target < targetSummaries[j].Target })

	summary := struct {
		Profile string `json:"profile"`
		Total   struct {
			Targets int `json:"targets"`
			Hosts   int `json:"hosts"`
			Ports   int `json:"ports"`
		} `json:"total"`
		Targets []struct {
			Target string `json:"target"`
			Hosts  int    `json:"hosts"`
			Ports  int    `json:"ports"`
		} `json:"targets"`
		Risks map[string]int `json:"risks"`
	}{
		Profile: req.Profile,
		Targets: targetSummaries,
		Risks:   risks,
	}
	summary.Total.Targets = len(reports)
	summary.Total.Hosts = totalHosts
	summary.Total.Ports = totalPorts

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(summary); err != nil {
		return reporting.OutputRecord{}, nil, err
	}
	meta := map[string]string{
		"summary_path":       path,
		"total_hosts":        fmt.Sprintf("%d", totalHosts),
		"total_ports":        fmt.Sprintf("%d", totalPorts),
		"targets":            strings.Join(targets, ","),
		"target_count":       fmt.Sprintf("%d", len(targets)),
		"profile":            profile,
		"cache.target_names": strings.Join(targets, ","),
	}
	embedRiskMetadata(meta, risks)
	setCacheMetadata(meta, inventoryCacheNamespace, cacheKey, "inventory-full", inventoryCacheTTL)
	_ = taskcache.SaveFile(inventoryCacheNamespace, cacheKey, path, meta)
	return reporting.OutputRecord{Label: "资产扫描汇总", Path: path}, meta, nil
}

func evaluateInventoryRisk(ports []assets.PortInfo) map[string]int {
	risk := make(map[string]int)
	for _, p := range ports {
		portRisk := classifyPortRisk(p.Port)
		if portRisk != "" {
			risk[portRisk]++
		}
	}
	return risk
}

func classifyPortRisk(port int) string {
	switch port {
	case 3389, 445, 5900:
		return "high"
	case 22, 21, 23:
		return "medium"
	case 80, 443, 8080:
		return "low"
	default:
		return ""
	}
}

const fastPorts = "80,443,22,3389,8080,8443,3306,5432,1433,27017"

type inventoryHost struct {
	IP         string    `json:"ip"`
	Hostname   string    `json:"hostname,omitempty"`
	Status     string    `json:"status"`
	LastSeen   time.Time `json:"last_seen"`
	OS         string    `json:"os,omitempty"`
	Confidence float64   `json:"confidence,omitempty"`
}

type inventoryPort struct {
	IP         string  `json:"ip"`
	Port       int     `json:"port"`
	State      string  `json:"state"`
	Service    string  `json:"service,omitempty"`
	Banner     string  `json:"banner,omitempty"`
	Protocol   string  `json:"protocol"`
	Confidence float64 `json:"confidence,omitempty"`
}

func sanitizeFileComponent(s string) string {
	replacer := strings.NewReplacer("/", "_", "\\", "_", ":", "_", "*", "_", "?", "_", "\"", "_", "<", "_", ">", "_", "|", "_", " ", "_")
	processed := replacer.Replace(s)
	if processed == "" {
		return "target"
	}
	return processed
}

func optionsToMap(o assets.ScanOptions) map[string]any {
	return map[string]any{
		"discovery":      o.DiscoveryMethod,
		"scan_method":    o.ScanMethod,
		"ports":          o.Ports,
		"timeout":        o.Timeout,
		"rate_limit":     o.RateLimit,
		"local_scan":     o.LocalScan,
		"arp_scan":       o.ArpScan,
		"hosts_only":     o.HostDiscoveryOnly,
		"resolve":        o.ResolveHostname,
		"banner":         o.GetBanner,
		"service_detect": o.EnableServiceDetect,
		"os_detect":      o.EnableOSDetect,
		"interface":      o.Interface,
		"verbose":        o.Verbose,
		"debug":          o.Debug,
		"concurrency":    o.Concurrency,
	}
}

func inventoryCacheKey(profile string, targets []string, opts assets.ScanOptions, flags map[string]any) string {
	normalizedTargets := append([]string(nil), targets...)
	sort.Strings(normalizedTargets)
	builder := strings.Builder{}
	builder.WriteString(strings.ToLower(profile))
	builder.WriteString("|targets=")
	builder.WriteString(strings.Join(normalizedTargets, ","))
	builder.WriteString("|ports=")
	builder.WriteString(opts.Ports)
	builder.WriteString("|method=")
	builder.WriteString(opts.ScanMethod)
	builder.WriteString("|discovery=")
	builder.WriteString(opts.DiscoveryMethod)
	builder.WriteString("|flags=")
	builder.WriteString(hashFlags(flags))
	sum := sha256.Sum256([]byte(builder.String()))
	return hex.EncodeToString(sum[:])
}

func cacheInventoryTarget(cacheKey string, report inventoryReport) {
	if report.OutputRecord.Path == "" {
		return
	}
	meta := map[string]string{
		"target": report.Target,
		"label":  report.OutputRecord.Label,
	}
	embedRiskMetadata(meta, report.Risks)
	setCacheMetadata(meta, inventoryTargetCacheNamespace, inventoryTargetCacheKey(cacheKey, report.Target), "inventory-target", inventoryCacheTTL)
	_ = taskcache.SaveFile(inventoryTargetCacheNamespace, inventoryTargetCacheKey(cacheKey, report.Target), report.OutputRecord.Path, meta)
}

func restoreInventoryFromCache(req TaskRequest, cacheKey string) (TaskResult, bool, error) {
	file, path, err := req.Manager.CreateFile("inventory", req.Name+"-summary", "json")
	if err != nil {
		return TaskResult{}, false, err
	}
	file.Close()
	meta, ok, err := taskcache.RestoreTo(inventoryCacheNamespace, cacheKey, inventoryCacheTTL, path)
	if err != nil || !ok {
		_ = os.Remove(path)
		return TaskResult{}, ok, err
	}
	markCacheHit(meta, inventoryCacheTTL)
	resultMetadata := cloneStringMap(meta)
	if resultMetadata == nil {
		resultMetadata = make(map[string]string)
	}
	targets := parseCachedTargets(meta["cache.target_names"])
	outputs := make([]reporting.OutputRecord, 0, len(targets)+1)
	riskTotals := metadataToRisk(meta)
	for _, target := range targets {
		out, risks, ok, err := restoreInventoryTargetArtifact(req, cacheKey, target)
		if err != nil || !ok {
			_ = os.Remove(path)
			return TaskResult{}, ok, err
		}
		outputs = append(outputs, out)
		accumulateRisk(riskTotals, risks)
	}
	outputs = append(outputs, reporting.OutputRecord{Label: "资产扫描汇总", Path: path})
	return TaskResult{
		Outputs:  outputs,
		Risks:    riskTotals,
		Metadata: resultMetadata,
		Notes:    []string{"命中资产扫描缓存"},
	}, true, nil
}

func restoreInventoryTargetArtifact(req TaskRequest, cacheKey, target string) (reporting.OutputRecord, map[string]int, bool, error) {
	file, path, err := req.Manager.CreateFile("inventory", fmt.Sprintf("%s-%s", req.Name, sanitizeFileComponent(target)), "json")
	if err != nil {
		return reporting.OutputRecord{}, nil, false, err
	}
	file.Close()
	meta, ok, err := taskcache.RestoreTo(inventoryTargetCacheNamespace, inventoryTargetCacheKey(cacheKey, target), inventoryCacheTTL, path)
	if err != nil || !ok {
		_ = os.Remove(path)
		return reporting.OutputRecord{}, nil, ok, err
	}
	markCacheHit(meta, inventoryCacheTTL)
	label := meta["label"]
	if label == "" {
		label = fmt.Sprintf("资产扫描：%s", target)
	}
	return reporting.OutputRecord{Label: label, Path: path}, metadataToRisk(meta), true, nil
}

func inventoryTargetCacheKey(cacheKey, target string) string {
	return cacheKey + "|" + strings.ToLower(strings.TrimSpace(target))
}

func parseCachedTargets(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	items := strings.Split(raw, ",")
	out := make([]string, 0, len(items))
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item != "" {
			out = append(out, item)
		}
	}
	return out
}
