package tasks

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/m-sec-org/d-eyes/agent/internal/assets"
	"github.com/m-sec-org/d-eyes/agent/internal/progress"
	"github.com/m-sec-org/d-eyes/agent/pkg/reporting"
)

type inventoryRunner struct{}

func InventoryRunner() TaskRunner {
	return &inventoryRunner{}
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
	baseOptions := buildInventoryOptions(profile, req.Flags)

	results := make([]inventoryReport, 0, len(targets))
	outputs := make([]reporting.OutputRecord, 0, len(targets)+1)
	riskTotals := make(map[string]int)

	for _, target := range targets {
		select {
		case <-ctx.Done():
			return TaskResult{Outputs: outputs, Risks: riskTotals, Notes: []string{"任务被取消"}}, ctx.Err()
		default:
		}
		report, err := r.scanTarget(ctx, target, baseOptions, req)
		if err != nil {
			return TaskResult{}, err
		}
		results = append(results, report)
		outputs = append(outputs, report.OutputRecord)
		accumulateRisk(riskTotals, report.Risks)
	}

	if summaryRecord, err := writeInventorySummary(req, results, riskTotals); err == nil && summaryRecord.Path != "" {
		outputs = append(outputs, summaryRecord)
	}

	return TaskResult{
		Outputs: outputs,
		Risks:   riskTotals,
	}, nil
}

type inventoryReport struct {
	Target       string
	Hosts        []assets.HostInfo
	Ports        []assets.PortInfo
	OutputRecord reporting.OutputRecord
	Risks        map[string]int
}

func (r *inventoryRunner) scanTarget(ctx context.Context, target string, opts assets.ScanOptions, req TaskRequest) (inventoryReport, error) {
	scanner := assets.CreateScannerFromOptions(opts)
	if scanner == nil {
		return inventoryReport{}, fmt.Errorf("无法创建扫描器")
	}
	manager := progress.NewManager(progress.NullReporter{}, 500*time.Millisecond, opts.Debug)
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

func writeInventorySummary(req TaskRequest, reports []inventoryReport, risks map[string]int) (reporting.OutputRecord, error) {
	file, path, err := req.Manager.CreateFile("inventory", req.Name+"-summary", "json")
	if err != nil {
		return reporting.OutputRecord{}, err
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
		return reporting.OutputRecord{}, err
	}
	return reporting.OutputRecord{Label: "资产扫描汇总", Path: path}, nil
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
