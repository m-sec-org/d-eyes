package tasks

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v4/host"
	"github.com/shirou/gopsutil/v4/process"

	"github.com/m-sec-org/d-eyes/agent/pkg/reporting"
)

type moduleResult struct {
	Outputs []reporting.OutputRecord
	Risks   map[string]int
	Notes   []string
}

func runHostSummary(ctx context.Context, req TaskRequest) (moduleResult, error) {
	info, err := host.InfoWithContext(ctx)
	if err != nil {
		return moduleResult{}, err
	}
	users, _ := host.UsersWithContext(ctx)
	hostname, _ := os.Hostname()
	summary := map[string]any{
		"hostname":       hostname,
		"os":             fmt.Sprintf("%s %s", info.Platform, info.PlatformVersion),
		"kernel":         fmt.Sprintf("%s %s", info.KernelArch, info.KernelVersion),
		"uptime_seconds": info.Uptime,
		"boot_time":      time.Unix(int64(info.BootTime), 0).Format(time.RFC3339),
		"virtualization": info.VirtualizationSystem,
		"hostid":         info.HostID,
		"go_arch":        runtime.GOARCH,
		"go_os":          runtime.GOOS,
	}
	usernames := make([]string, 0, len(users))
	for _, u := range users {
		usernames = append(usernames, u.User)
	}
	summary["logged_in_users"] = usernames

	file, path, err := req.Manager.CreateFile("respond", req.Name+"-host-summary", "json")
	if err != nil {
		return moduleResult{}, err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(summary); err != nil {
		return moduleResult{}, err
	}
	return moduleResult{
		Outputs: []reporting.OutputRecord{{Label: "主机概要", Path: path}},
	}, nil
}

func runFileScan(ctx context.Context, req TaskRequest) (moduleResult, error) {
	targets := parseTargets(req)
	if len(targets) == 0 {
		targets = []string{"."}
	}
	const maxSamples = 50
	type suspiciousFile struct {
		Path     string    `json:"path"`
		Reason   string    `json:"reason"`
		Size     int64     `json:"size"`
		Modified time.Time `json:"modified"`
	}
	summary := struct {
		Targets          []string         `json:"targets"`
		ScannedFiles     int              `json:"scanned_files"`
		SuspiciousFiles  int              `json:"suspicious_files"`
		SampleSuspicious []suspiciousFile `json:"sample_suspicious"`
		Errors           []string         `json:"errors"`
	}{
		Targets: targets,
	}
	suspiciousSamples := make([]suspiciousFile, 0, maxSamples)
	suspiciousCount := 0
	extensions := map[string]string{
		".exe":   "可执行文件",
		".dll":   "动态链接库",
		".ps1":   "PowerShell 脚本",
		".bat":   "批处理脚本",
		".sh":    "Shell 脚本",
		".php":   "可能的 WebShell",
		".jsp":   "可能的 WebShell",
		".war":   "可能的部署包",
		".pyc":   "编译后的 Python 文件",
		".class": "Java 字节码",
	}
	keywords := []string{"tmp", "cache", "backup", "shadow", "hidden", ".bak"}
	walkCtx := ctx
	for _, target := range targets {
		err := filepath.WalkDir(target, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				summary.Errors = append(summary.Errors, err.Error())
				return nil
			}
			select {
			case <-walkCtx.Done():
				return walkCtx.Err()
			default:
			}
			if d.IsDir() {
				return nil
			}
			summary.ScannedFiles++
			info, err := d.Info()
			if err != nil {
				return nil
			}
			name := strings.ToLower(info.Name())
			reason := ""
			if r, ok := extensions[filepath.Ext(name)]; ok {
				reason = r
			}
			if reason == "" {
				for _, kw := range keywords {
					if strings.Contains(name, kw) {
						reason = fmt.Sprintf("文件名包含关键字 %s", kw)
						break
					}
				}
			}
			if reason != "" {
				suspiciousCount++
				if len(suspiciousSamples) < maxSamples {
					suspiciousSamples = append(suspiciousSamples, suspiciousFile{
						Path:     path,
						Reason:   reason,
						Size:     info.Size(),
						Modified: info.ModTime(),
					})
				}
			}
			return nil
		})
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return moduleResult{}, err
		}
	}
	summary.SuspiciousFiles = suspiciousCount
	summary.SampleSuspicious = suspiciousSamples

	file, path, err := req.Manager.CreateFile("respond", req.Name+"-filescan", "json")
	if err != nil {
		return moduleResult{}, err
	}
	defer file.Close()
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(summary); err != nil {
		return moduleResult{}, err
	}
	risk := map[string]int{}
	if suspiciousCount > 0 {
		risk["high"] = suspiciousCount
	}
	return moduleResult{
		Outputs: []reporting.OutputRecord{{Label: "文件扫描", Path: path}},
		Risks:   risk,
	}, nil
}

func runNetworkAnalysis(ctx context.Context, req TaskRequest) (moduleResult, error) {
	processes, err := process.ProcessesWithContext(ctx)
	if err != nil {
		return moduleResult{}, err
	}
	type connection struct {
		PID     int32  `json:"pid"`
		Process string `json:"process"`
		Local   string `json:"local"`
		Remote  string `json:"remote"`
		Status  string `json:"status"`
		User    string `json:"user"`
	}
	connections := make([]connection, 0, 64)
	externalCount := 0
	for _, proc := range processes {
		select {
		case <-ctx.Done():
			return moduleResult{}, ctx.Err()
		default:
		}
		conns, err := proc.ConnectionsWithContext(ctx)
		if err != nil {
			continue
		}
		if len(conns) == 0 {
			continue
		}
		cmdline, _ := proc.Cmdline()
		if cmdline == "" {
			cmdline, _ = proc.Name()
		}
		username, _ := proc.Username()
		for _, conn := range conns {
			if conn.Raddr.IP == "" || conn.Status == "LISTEN" {
				continue
			}
			local := fmt.Sprintf("%s:%d", conn.Laddr.IP, conn.Laddr.Port)
			remote := fmt.Sprintf("%s:%d", conn.Raddr.IP, conn.Raddr.Port)
			connections = append(connections, connection{
				PID:     proc.Pid,
				Process: cmdline,
				Local:   local,
				Remote:  remote,
				Status:  conn.Status,
				User:    username,
			})
			if !isPrivateIP(conn.Raddr.IP) {
				externalCount++
			}
		}
	}

	report := struct {
		Connections   []connection `json:"connections"`
		ExternalCount int          `json:"external_connections"`
	}{Connections: connections, ExternalCount: externalCount}

	file, path, err := req.Manager.CreateFile("respond", req.Name+"-network", "json")
	if err != nil {
		return moduleResult{}, err
	}
	defer file.Close()
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(report); err != nil {
		return moduleResult{}, err
	}
	risk := map[string]int{}
	if externalCount > 0 {
		risk["medium"] = externalCount
	}
	return moduleResult{
		Outputs: []reporting.OutputRecord{{Label: "网络连接", Path: path}},
		Risks:   risk,
	}, nil
}

func runUserInspection(ctx context.Context, req TaskRequest) (moduleResult, error) {
	users, err := host.UsersWithContext(ctx)
	if err != nil {
		return moduleResult{}, err
	}
	summary := struct {
		ActiveSessions int             `json:"active_sessions"`
		Users          []host.UserStat `json:"sessions"`
		Notes          []string        `json:"notes"`
	}{ActiveSessions: len(users), Users: users}

	file, path, err := req.Manager.CreateFile("respond", req.Name+"-users", "json")
	if err != nil {
		return moduleResult{}, err
	}
	defer file.Close()
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(summary); err != nil {
		return moduleResult{}, err
	}
	risk := map[string]int{}
	if len(users) > 10 {
		risk["low"] = len(users)
	}
	return moduleResult{
		Outputs: []reporting.OutputRecord{{Label: "用户会话", Path: path}},
		Risks:   risk,
	}, nil
}

func accumulateRisk(total map[string]int, part map[string]int) {
	if part == nil {
		return
	}
	for k, v := range part {
		total[strings.ToLower(k)] += v
	}
}

func parseTargets(req TaskRequest) []string {
	val, ok := req.Flags["targets"]
	if !ok {
		return nil
	}
	switch t := val.(type) {
	case string:
		if strings.TrimSpace(t) == "" {
			return nil
		}
		items := strings.Split(t, ",")
		out := make([]string, 0, len(items))
		for _, item := range items {
			item = strings.TrimSpace(item)
			if item != "" {
				out = append(out, item)
			}
		}
		return out
	default:
		return nil
	}
}

func isPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	privateBlocks := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"::1/128",
		"fc00::/7",
		"fe80::/10",
	}
	for _, block := range privateBlocks {
		_, cidr, _ := net.ParseCIDR(block)
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}
