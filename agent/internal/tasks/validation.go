package tasks

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/m-sec-org/d-eyes/agent/pkg/exit"
)

// ValidateRequest 根据命令名称校验任务请求所需的参数/默认值。
func ValidateRequest(command string, req *TaskRequest) error {
	if req == nil {
		return exit.New(64, fmt.Errorf("任务请求无效"))
	}
	switch command {
	case "respond":
		return validateRespond(req)
	case "inventory":
		return validateInventory(req)
	case "audit":
		return validateAudit(req)
	case "supplychain":
		return validateSupplyChain(req)
	case "baseline":
		return validateBaseline(req)
	case "bas":
		return validateBAS(req)
	default:
		return nil
	}
}

func validateRespond(req *TaskRequest) error {
	if req.Profile == "" || req.Profile == "default" {
		if profile := strings.TrimSpace(req.Config.Tasks.Respond.Profile); profile != "" {
			req.Profile = profile
		}
	}
	targets := parseTargets(*req)
	if len(targets) == 0 {
		cfgTargets := req.Config.Tasks.Respond.Targets
		if len(cfgTargets) == 0 {
			cfgTargets = req.Config.Discovery.Targets
		}
		if len(cfgTargets) == 0 {
			return exit.New(64, fmt.Errorf("respond 命令需要提供 --targets 或在配置 config.tasks.respond.targets / config.discovery.targets 中定义默认值"))
		}
		applyTargets(req, cfgTargets)
		message := fmt.Sprintf("未指定 --targets，使用配置项默认值：%s", strings.Join(cfgTargets, ", "))
		req.Notices = append(req.Notices, message)
	}
	return nil
}

func validateInventory(req *TaskRequest) error {
	if req.Profile == "" || req.Profile == "default" {
		if profile := strings.TrimSpace(req.Config.Tasks.Inventory.Profile); profile != "" {
			req.Profile = profile
		}
	}
	targets := parseTargets(*req)
	if len(targets) == 0 {
		cfgTargets := req.Config.Tasks.Inventory.Targets
		if len(cfgTargets) == 0 {
			cfgTargets = req.Config.Discovery.Targets
		}
		if len(cfgTargets) > 0 {
			applyTargets(req, cfgTargets)
			targets = cfgTargets
		}
	}
	if len(targets) == 0 {
		return exit.New(64, fmt.Errorf("inventory 命令需要 --targets 或配置 config.discovery.targets"))
	}

	ports := getStringFlag(req.Flags, "ports", "")
	if ports == "" && strings.TrimSpace(req.Config.Tasks.Inventory.Ports) != "" {
		ports = strings.TrimSpace(req.Config.Tasks.Inventory.Ports)
		req.Flags["ports"] = ports
	}
	if ports != "" {
		if err := validatePortList(ports); err != nil {
			return exit.New(64, err)
		}
	}
	return nil
}

func validateAudit(req *TaskRequest) error {
	scope := strings.TrimSpace(getStringFlag(req.Flags, "scope", ""))
	if scope == "" {
		scope = strings.TrimSpace(req.Config.Tasks.Audit.Scope)
	}
	if scope == "" {
		scope = "system"
	}
	req.Flags["scope"] = scope

	if len(parseTargets(*req)) == 0 && len(req.Config.Tasks.Audit.Targets) > 0 {
		applyTargets(req, req.Config.Tasks.Audit.Targets)
	}
	return nil
}

func validateSupplyChain(req *TaskRequest) error {
	mode := strings.ToLower(strings.TrimSpace(getStringFlag(req.Flags, "mode", "")))
	if mode == "" {
		mode = strings.ToLower(strings.TrimSpace(req.Config.Tasks.SupplyChain.Mode))
	}
	if mode == "" {
		mode = "generate"
	}
	if mode != "generate" && mode != "capture" {
		return exit.New(64, fmt.Errorf("supplychain 命令的 --mode 仅支持 generate 或 capture"))
	}
	req.Flags["mode"] = mode

	pathVal := strings.TrimSpace(getStringFlag(req.Flags, "path", ""))
	if pathVal == "" && len(req.Config.Tasks.SupplyChain.Paths) > 0 {
		pathVal = strings.Join(req.Config.Tasks.SupplyChain.Paths, ",")
		req.Flags["path"] = pathVal
	}
	fileVal := strings.TrimSpace(getStringFlag(req.Flags, "file", ""))
	if fileVal == "" && strings.TrimSpace(req.Config.Tasks.SupplyChain.File) != "" {
		fileVal = strings.TrimSpace(req.Config.Tasks.SupplyChain.File)
		req.Flags["file"] = fileVal
	}

	if mode == "generate" && pathVal == "" && fileVal == "" {
		return exit.New(64, fmt.Errorf("supplychain generate 需要通过 --path 或 --file 指定输入，或在配置 config.tasks.supplychain.paths / file 中设置默认值"))
	}

	outputType := strings.TrimSpace(getStringFlag(req.Flags, "type", ""))
	if outputType == "" && strings.TrimSpace(req.Config.Tasks.SupplyChain.Type) != "" {
		req.Flags["type"] = strings.TrimSpace(req.Config.Tasks.SupplyChain.Type)
	}

	return nil
}

func validateBaseline(req *TaskRequest) error {
	scope := strings.TrimSpace(getStringFlag(req.Flags, "scope", ""))
	if scope == "" {
		scope = strings.TrimSpace(req.Config.Tasks.Baseline.Scope)
	}
	if scope == "" {
		scope = "all"
	}
	req.Flags["scope"] = scope

	configPath := strings.TrimSpace(getStringFlag(req.Flags, "baseline-config", ""))
	if configPath == "" && strings.TrimSpace(req.Config.Tasks.Baseline.Config) != "" {
		configPath = strings.TrimSpace(req.Config.Tasks.Baseline.Config)
		req.Flags["baseline-config"] = configPath
	}
	if configPath != "" {
		if err := ensureFileExists(configPath); err != nil {
			return exit.New(64, fmt.Errorf("baseline 配置文件不可用: %w", err))
		}
	}
	return nil
}

func validateBAS(req *TaskRequest) error {
	if req.Flags == nil {
		req.Flags = make(map[string]any)
	}
	if req.Metadata == nil {
		req.Metadata = make(map[string]string)
	}
	var provided bool

	if raw := req.Flags["scenario"]; raw != nil {
		switch v := raw.(type) {
		case string:
			if strings.TrimSpace(v) != "" {
				provided = true
			}
		case []byte:
			if strings.TrimSpace(string(v)) != "" {
				provided = true
			}
		case map[string]any:
			if len(v) > 0 {
				provided = true
			}
		}
	}

	if id := strings.TrimSpace(getStringFlag(req.Flags, "scenario-id", "")); id != "" {
		req.Flags["scenario-id"] = id
		provided = true
	}

	if getBoolFlag(req.Flags, "sandbox-approve") {
		req.SandboxApproved = true
		req.Metadata["sandbox_approved"] = "true"
	}

	if !provided {
		if path := strings.TrimSpace(getStringFlag(req.Flags, "scenario-file", "")); path != "" {
			if _, err := os.Stat(path); err == nil {
				provided = true
			} else {
				return exit.New(64, fmt.Errorf("scenario 文件不可访问: %w", err))
			}
		}
	}

	if !provided {
		return exit.New(64, errors.New("BAS 任务需要提供 --scenario、--scenario-id 或 --scenario-file"))
	}

	useSandbox := req.Config.Sandbox.Enabled && req.Config.Tasks.BAS.SandboxEnabled
	if getBoolFlag(req.Flags, "sandbox") {
		useSandbox = true
	}
	if getBoolFlag(req.Flags, "no-sandbox") {
		useSandbox = false
	}
	if useSandbox {
		req.Metadata["sandbox_requested"] = "true"
		if req.Config.Sandbox.RequireApproval && !req.SandboxApproved {
			return exit.New(65, errors.New("沙箱执行需要审批，请设置 metadata.sandbox_approved=true 后重试"))
		}
	}
	req.Config.Sandbox.Enabled = useSandbox

	return nil
}

func applyTargets(req *TaskRequest, targets []string) {
	if len(targets) == 0 {
		return
	}
	clean := make([]string, 0, len(targets))
	for _, t := range targets {
		t = strings.TrimSpace(t)
		if t != "" {
			clean = append(clean, t)
		}
	}
	if len(clean) == 0 {
		return
	}
	req.Flags["targets"] = strings.Join(clean, ",")
}

func validatePortList(value string) error {
	parts := strings.Split(value, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, "-") {
			bounds := strings.SplitN(part, "-", 2)
			if len(bounds) != 2 {
				return fmt.Errorf("端口范围格式无效: %s", part)
			}
			start, err1 := strconv.Atoi(strings.TrimSpace(bounds[0]))
			end, err2 := strconv.Atoi(strings.TrimSpace(bounds[1]))
			if err1 != nil || err2 != nil || start <= 0 || end <= 0 || start > 65535 || end > 65535 || start > end {
				return fmt.Errorf("端口范围格式无效: %s", part)
			}
			continue
		}
		port, err := strconv.Atoi(part)
		if err != nil || port <= 0 || port > 65535 {
			return fmt.Errorf("端口值非法: %s", part)
		}
	}
	return nil
}

func ensureFileExists(path string) error {
	if path == "" {
		return fmt.Errorf("文件路径为空")
	}
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if info.IsDir() {
		return fmt.Errorf("%s 是目录", filepath.Clean(path))
	}
	return nil
}
