package internal

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	fatihColor "github.com/fatih/color"
	"github.com/urfave/cli/v2"

	"github.com/m-sec-org/d-eyes/agent/internal/tasks"
	"github.com/m-sec-org/d-eyes/agent/pkg/config"
	"github.com/m-sec-org/d-eyes/agent/pkg/reporting"
	"github.com/m-sec-org/d-eyes/agent/pkg/threatintel"
)

var (
	version    = "v1.3.1"
	configPath string

	loadedConfigPath string
	loadedConfigMu   sync.RWMutex

	taskRegistryMu sync.RWMutex
	taskRegistry   = make(map[string]taskCommandDefinition)
)

// RunnerFactory 构建各任务的 Runner，允许在测试或插件中注入自定义依赖。
type RunnerFactory interface {
	RespondRunner() tasks.TaskRunner
	AuditRunner() tasks.TaskRunner
	InventoryRunner() tasks.TaskRunner
	SupplyChainRunner() tasks.TaskRunner
	BaselineRunner() tasks.TaskRunner
	BASRunner() tasks.TaskRunner
	ActionRunner() tasks.TaskRunner
}

type defaultRunnerFactory struct{}

// DefaultRunnerFactory 返回生产环境使用的默认 Runner 工厂。
func DefaultRunnerFactory() RunnerFactory {
	return defaultRunnerFactory{}
}

func (defaultRunnerFactory) RespondRunner() tasks.TaskRunner {
	return tasks.RespondRunnerWithSelector(nil)
}

func (defaultRunnerFactory) AuditRunner() tasks.TaskRunner {
	return tasks.AuditRunner()
}

func (defaultRunnerFactory) InventoryRunner() tasks.TaskRunner {
	return tasks.InventoryRunnerWithExecutor(nil)
}

func (defaultRunnerFactory) SupplyChainRunner() tasks.TaskRunner {
	return tasks.SupplyChainRunnerWithCollector(nil)
}

func (defaultRunnerFactory) BaselineRunner() tasks.TaskRunner {
	return tasks.BaselineRunnerWithExecutor(nil)
}

func (defaultRunnerFactory) BASRunner() tasks.TaskRunner {
	return tasks.BASRunnerWithDeps(nil, nil, nil)
}

func (defaultRunnerFactory) ActionRunner() tasks.TaskRunner {
	return tasks.ActionTaskRunner()
}

func ensureRunnerFactory(factory RunnerFactory) RunnerFactory {
	if factory == nil {
		return DefaultRunnerFactory()
	}
	return factory
}

func registerDefaultTasks(factory RunnerFactory) []taskCommandDefinition {
	defs := defaultTaskDefinitions(factory)
	for _, def := range defs {
		registerTaskDefinition(def)
	}
	return defs
}

// EnsureDefaultTaskRunners 确保全局任务注册表使用指定工厂生成的 Runner。
func EnsureDefaultTaskRunners(factory RunnerFactory) {
	registerDefaultTasks(factory)
}

func applyTaskDefinitions(defs []taskCommandDefinition) map[string]taskCommandDefinition {
	prev := make(map[string]taskCommandDefinition, len(defs))
	taskRegistryMu.Lock()
	defer taskRegistryMu.Unlock()
	for _, def := range defs {
		if existing, ok := taskRegistry[def.Name]; ok {
			prev[def.Name] = existing
		}
		taskRegistry[def.Name] = def
	}
	return prev
}

// App 提供向后兼容的默认 CLI 实例。
var App = NewApp()

// NewApp 返回初始化后的 CLI 应用实例，供内嵌或测试场景复用。
func NewApp() *cli.App {
	app := cli.NewApp()
	app.Name = "d-eyes"
	app.Usage = "The Eyes of Darkness from Nsfocus spy on everything."
	app.Description = "D-Eyes 是一款综合性安全扫描工具，用于发现和识别潜在的安全风险。"
	app.CustomAppHelpTemplate = `NAME:
   {{.HelpName}} - {{if .Usage}}{{.Usage}}{{else}}{{.Description}}{{end}}

USAGE:
   {{if .VisibleFlags}}{{.HelpName}} [global options]{{end}} command [command options] [arguments...]

COMMANDS:
{{range .VisibleCategories}}{{if .Name}}{{.Name}}:
{{end}}{{range .VisibleCommands}}   {{join .Names ", "}}{{"\t"}}{{.Usage}}
{{end}}
{{end}}{{if .VisibleFlags}}
GLOBAL OPTIONS:
{{range .VisibleFlags}}{{"\t"}}{{.}}
{{end}}{{end}}`

	app.Commands = []*cli.Command{
		{
			Name:     "version",
			Aliases:  []string{"v"},
			Usage:    "Show the version of d-eyes",
			Category: "Integration",
			Action: func(c *cli.Context) error {
				fmt.Printf("D-Eyes %s\n", version)
				fmt.Printf("操作系统: %s\n", runtime.GOOS)
				fmt.Printf("架构: %s\n", runtime.GOARCH)
				return nil
			},
		},
	}

	for _, def := range registerDefaultTasks(nil) {
		app.Commands = append(app.Commands, newTaskCommand(def))
	}

	app.Flags = []cli.Flag{
		&cli.StringFlag{
			Name:        "config",
			Usage:       "指定配置文件路径，默认为 ~/.d-eyes/config.yaml",
			Destination: &configPath,
			EnvVars:     []string{"D_EYES_CONFIG"},
		},
		&cli.StringFlag{
			Name:  "profile",
			Usage: "指定任务配置档案，共享于所有操作类命令",
		},
		&cli.StringFlag{
			Name:  "output-dir",
			Usage: "指定报告输出目录，所有任务默认写入该目录",
		},
		&cli.StringFlag{
			Name:  "format",
			Usage: "指定报告格式，例如 json、html",
		},
		&cli.StringFlag{
			Name:  "name",
			Usage: "自定义任务名称，用于报告命名与摘要展示",
		},
		&cli.DurationFlag{
			Name:  "timeout",
			Usage: "任务超时时间，支持 30s、5m 等格式",
		},
		&cli.BoolFlag{
			Name:  "json",
			Usage: "以 JSON 格式输出任务摘要，便于自动化处理",
		},
		&cli.BoolFlag{
			Name:  "quiet",
			Usage: "启用静默模式，仅生成报告文件，不在终端输出摘要",
		},
		&cli.StringFlag{
			Name:    "ti-mode",
			Usage:   "威胁情报模式：auto、local、hybrid 或 server（默认 hybrid）",
			EnvVars: []string{"D_EYES_TI_MODE"},
		},
	}
	app.Before = func(c *cli.Context) error {
		SetQuietMode(false)
		path := configPath
		if path == "" {
			path = defaultConfigPath()
		}
		cfg, err := config.Load(path)
		if err != nil {
			return err
		}
		SetGlobalConfig(cfg)
		setLoadedConfigPath(path)
		fatihColor.NoColor = !cfg.UI.Color
		if c.App.Metadata == nil {
			c.App.Metadata = make(map[string]interface{})
		}
		c.App.Metadata["configPath"] = path
		return nil
	}
	return app
}

func defaultTaskDefinitions(factory RunnerFactory) []taskCommandDefinition {
	factory = ensureRunnerFactory(factory)
	return []taskCommandDefinition{
		{
			Name:        "respond",
			Usage:       "综合各模块能力执行综合安全分析任务",
			Description: "面向安全事件的快速排查流程，包含恶意文件扫描、网络连接分析等子任务组合。",
			Category:    "Operations",
			Runner:      factory.RespondRunner(),
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:  "targets",
					Usage: "逗号分隔的扫描目标路径",
				},
			},
		},
		{
			Name:        "audit",
			Usage:       "执行合规审计任务",
			Description: "聚焦操作系统、账号和配置的基线审计流程，输出整改建议。",
			Category:    "Operations",
			Runner:      factory.AuditRunner(),
		},
		{
			Name:        "inventory",
			Usage:       "执行资产梳理任务",
			Description: "对网络范围进行主机与端口巡检，生成资产清单。",
			Category:    "Operations",
			Runner:      factory.InventoryRunner(),
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:  "targets",
					Usage: "逗号分隔的扫描目标（IP、CIDR、域名）",
				},
				&cli.StringFlag{
					Name:  "ports",
					Usage: "自定义端口范围，例如 80,443,1000-2000",
				},
				&cli.BoolFlag{
					Name:  "service-detect",
					Usage: "启用服务指纹识别",
				},
				&cli.BoolFlag{
					Name:  "os-detect",
					Usage: "启用操作系统识别",
				},
				&cli.BoolFlag{
					Name:  "resolve",
					Usage: "解析主机名",
				},
			},
		},
		{
			Name:        "supplychain",
			Usage:       "执行供应链安全任务",
			Description: "生成或采集 SBOM 清单，分析依赖风险。",
			Category:    "Operations",
			Runner:      factory.SupplyChainRunner(),
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:  "mode",
					Usage: "运行模式: generate（默认）或 capture",
				},
				&cli.StringFlag{
					Name:  "path",
					Usage: "待扫描的项目路径",
				},
				&cli.StringFlag{
					Name:  "file",
					Usage: "待扫描的依赖清单文件",
				},
				&cli.StringFlag{
					Name:  "type",
					Usage: "输出格式: json 或 xml",
				},
				&cli.BoolFlag{
					Name:  "offline",
					Usage: "启用离线模式（跳过网络检查）",
				},
			},
		},
		{
			Name:        "baseline",
			Usage:       "执行基线检查任务",
			Description: "调度系统安全基线检查，输出风险统计与修复建议。",
			Category:    "Operations",
			Runner:      factory.BaselineRunner(),
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:  "scope",
					Usage: "基线检查范围，例如 all、os、db",
				},
				&cli.StringFlag{
					Name:  "baseline-config",
					Usage: "基线检查配置文件路径",
				},
			},
		},
		{
			Name:        "bas",
			Usage:       "执行 BAS（攻击模拟）任务",
			Description: "运行预定义或自定义的攻击场景，验证防御与响应能力。",
			Category:    "Operations",
			Runner:      factory.BASRunner(),
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:  "scenario",
					Usage: "内置场景 ID 或 JSON 定义，覆盖默认配置",
				},
				&cli.StringFlag{
					Name:  "scenario-id",
					Usage: "指定内置 BAS 场景 ID（如 initial-access）",
				},
				&cli.StringFlag{
					Name:  "scenario-file",
					Usage: "指定包含场景描述的 JSON/YAML 文件路径",
				},
				&cli.BoolFlag{
					Name:  "sandbox",
					Usage: "强制启用沙箱执行（覆盖配置）",
				},
				&cli.BoolFlag{
					Name:  "no-sandbox",
					Usage: "禁用沙箱执行，仅用于调试场景",
				},
				&cli.BoolFlag{
					Name:  "sandbox-approve",
					Usage: "显式批准沙箱执行，适用于需要审批的环境",
				},
			},
		},
		{
			Name:        "action",
			Usage:       "执行来自 Server 的响应动作",
			Description: "由自动化 Playbook 调度的即时操作，例如隔离进程、阻断网络等。",
			Category:    "Automation",
			Runner:      factory.ActionRunner(),
		},
	}
}

func registerTaskDefinition(def taskCommandDefinition) {
	applyTaskDefinitions([]taskCommandDefinition{def})
}

// OverrideRunnerFactoryForTesting 允许测试场景批量替换内置 Runner，返回恢复函数。
func OverrideRunnerFactoryForTesting(factory RunnerFactory) func() {
	if factory == nil {
		panic("override runner factory: factory is nil")
	}
	defs := defaultTaskDefinitions(factory)
	prev := applyTaskDefinitions(defs)
	return func() {
		taskRegistryMu.Lock()
		defer taskRegistryMu.Unlock()
		for _, def := range defs {
			if original, ok := prev[def.Name]; ok {
				taskRegistry[def.Name] = original
			} else {
				delete(taskRegistry, def.Name)
			}
		}
	}
}

// OverrideTaskRunnerForTesting 替换指定任务的 Runner，返回恢复函数，仅供单元测试调用。
func OverrideTaskRunnerForTesting(name string, runner tasks.TaskRunner) func() {
	if strings.TrimSpace(name) == "" {
		panic("override task runner: name is empty")
	}
	if runner == nil {
		panic("override task runner: runner is nil")
	}
	taskRegistryMu.Lock()
	prev, existed := taskRegistry[name]
	taskRegistry[name] = taskCommandDefinition{
		Name:        name,
		Usage:       prev.Usage,
		Description: prev.Description,
		Category:    prev.Category,
		Runner:      runner,
		Flags:       prev.Flags,
	}
	taskRegistryMu.Unlock()
	return func() {
		taskRegistryMu.Lock()
		defer taskRegistryMu.Unlock()
		if existed {
			taskRegistry[name] = prev
			return
		}
		delete(taskRegistry, name)
	}
}

// RegisterCommand 注册插件到默认 App。
func RegisterCommand(c *cli.Command) {
	AttachCommand(App, c)
}

// AttachCommand 允许外部将命令附加到自定义 CLI App。
func AttachCommand(app *cli.App, c *cli.Command) {
	if app == nil {
		panic("plugin: target app is nil")
	}
	if c == nil {
		panic("plugin: Register plugin is nil")
	}
	app.Commands = append(app.Commands, c)
}

// TaskRunnerByName 查找已注册任务的 Runner。
func TaskRunnerByName(name string) (tasks.TaskRunner, bool) {
	taskRegistryMu.RLock()
	defer taskRegistryMu.RUnlock()
	def, ok := taskRegistry[name]
	if !ok {
		if idx := strings.IndexRune(name, '.'); idx > 0 {
			base := name[:idx]
			def, ok = taskRegistry[base]
		}
		if !ok {
			return nil, false
		}
	}
	return def.Runner, true
}

// TaskNames 返回所有内置任务名称。
func TaskNames() []string {
	taskRegistryMu.RLock()
	defer taskRegistryMu.RUnlock()
	names := make([]string, 0, len(taskRegistry))
	for name := range taskRegistry {
		names = append(names, name)
	}
	return names
}

type taskCommandDefinition struct {
	Name        string
	Usage       string
	Description string
	Category    string
	Runner      tasks.TaskRunner
	Flags       []cli.Flag
}

func newTaskCommand(def taskCommandDefinition) *cli.Command {
	return &cli.Command{
		Name:        def.Name,
		Usage:       def.Usage,
		Description: def.Description,
		Category:    def.Category,
		Flags:       def.Flags,
		Action: func(c *cli.Context) error {
			cfg := GetGlobalConfig()
			req := tasks.TaskRequest{
				Profile:    c.String("profile"),
				OutputDir:  c.String("output-dir"),
				Format:     c.String("format"),
				Name:       c.String("name"),
				Timeout:    c.Duration("timeout"),
				Flags:      tasks.ExtractFlags(c),
				Config:     cfg,
				Quiet:      c.Bool("quiet"),
				JSONOutput: c.Bool("json"),
			}
			if mode := strings.TrimSpace(c.String("ti-mode")); mode != "" {
				req.Config.ThreatIntel.Mode = threatintel.ParseMode(mode)
			}
			req.ApplyDefaults(def.Name)
			if err := tasks.ValidateRequest(def.Name, &req); err != nil {
				return err
			}

			manager := GetReportManager()
			if req.OutputDir != "" && req.OutputDir != cfg.Output.Dir {
				override := cfg
				override.Output.Dir = req.OutputDir
				manager = reporting.NewManager(override)
			}
			SetQuietMode(req.Quiet)
			runner := def.Runner
			if resolved, ok := TaskRunnerByName(def.Name); ok && resolved != nil {
				runner = resolved
			}
			return tasks.Execute(c.Context, def.Name, runner, req, manager)
		},
	}
}

func defaultConfigPath() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return filepath.Join(os.TempDir(), "d-eyes", "config.yaml")
	}
	return filepath.Join(home, ".d-eyes", "config.yaml")
}

func setLoadedConfigPath(path string) {
	loadedConfigMu.Lock()
	loadedConfigPath = path
	loadedConfigMu.Unlock()
}

// LoadedConfigPath returns the absolute path of the currently active config file.
func LoadedConfigPath() string {
	loadedConfigMu.RLock()
	defer loadedConfigMu.RUnlock()
	return loadedConfigPath
}
