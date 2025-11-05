package internal

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"

	fatihColor "github.com/fatih/color"
	"github.com/urfave/cli/v2"

	"github.com/m-sec-org/d-eyes/agent/internal/tasks"
	"github.com/m-sec-org/d-eyes/agent/pkg/config"
	"github.com/m-sec-org/d-eyes/agent/pkg/reporting"
)

var (
	version    = "v1.3.1"
	configPath string

	taskRegistryMu sync.RWMutex
	taskRegistry   = make(map[string]taskCommandDefinition)
)

// App 提供向后兼容的默认 CLI 实例。
var App = NewApp()

// NewApp 返回初始化后的 CLI 应用实例，供内嵌或测试场景复用。
func NewApp() *cli.App {
	app := cli.NewApp()
	app.Name = "d-eyes"
	app.Usage = "The Eyes of Darkness from Nsfocus spy on everything."
	app.Description = "D-Eyes 是一款综合性安全扫描工具，用于发现和识别潜在的安全风险。"
	app.Commands = []*cli.Command{
		{
			Name:    "version",
			Aliases: []string{"v"},
			Usage:   "Show the version of d-eyes",
			Action: func(c *cli.Context) error {
				fmt.Printf("D-Eyes %s\n", version)
				fmt.Printf("操作系统: %s\n", runtime.GOOS)
				fmt.Printf("架构: %s\n", runtime.GOARCH)
				return nil
			},
		},
	}

	for _, def := range defaultTaskDefinitions() {
		registerTaskDefinition(def)
		app.Commands = append(app.Commands, newTaskCommand(def))
	}

	app.Flags = []cli.Flag{
		&cli.StringFlag{
			Name:        "config",
			Usage:       "指定配置文件路径，默认为 ~/.d-eyes/config.yaml",
			Destination: &configPath,
			EnvVars:     []string{"D_EYES_CONFIG"},
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
		fatihColor.NoColor = !cfg.UI.Color
		if c.App.Metadata == nil {
			c.App.Metadata = make(map[string]interface{})
		}
		c.App.Metadata["configPath"] = path
		return nil
	}
	return app
}

func defaultTaskDefinitions() []taskCommandDefinition {
	return []taskCommandDefinition{
		{
			Name:        "respond",
			Usage:       "执行应急响应任务",
			Description: "面向安全事件的快速排查流程，包含恶意文件扫描、网络连接分析等子任务组合。",
			Runner:      tasks.RespondRunner(),
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
			Runner:      tasks.AuditRunner(),
		},
		{
			Name:        "inventory",
			Usage:       "执行资产梳理任务",
			Description: "对网络范围进行主机与端口巡检，生成资产清单。",
			Runner:      tasks.InventoryRunner(),
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
			Runner:      tasks.SupplyChainRunner(),
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
			Runner:      tasks.BaselineRunner(),
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
	}
}

func registerTaskDefinition(def taskCommandDefinition) {
	taskRegistryMu.Lock()
	defer taskRegistryMu.Unlock()
	taskRegistry[def.Name] = def
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
		return nil, false
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
	Runner      tasks.TaskRunner
	Flags       []cli.Flag
}

func newTaskCommand(def taskCommandDefinition) *cli.Command {
	flags := append(baseTaskFlags(), def.Flags...)
	return &cli.Command{
		Name:        def.Name,
		Usage:       def.Usage,
		Description: def.Description,
		Flags:       flags,
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
			req.ApplyDefaults(def.Name)

			manager := GetReportManager()
			if req.OutputDir != "" && req.OutputDir != cfg.Output.Dir {
				override := cfg
				override.Output.Dir = req.OutputDir
				manager = reporting.NewManager(override)
			}
			SetQuietMode(req.Quiet)
			return tasks.Execute(c.Context, def.Name, def.Runner, req, manager)
		},
	}
}

func baseTaskFlags() []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{
			Name:  "profile",
			Usage: "指定任务配置档案",
		},
		&cli.StringFlag{
			Name:  "output-dir",
			Usage: "指定报告输出目录",
		},
		&cli.StringFlag{
			Name:  "format",
			Usage: "指定报告格式",
		},
		&cli.StringFlag{
			Name:  "name",
			Usage: "自定义任务名称",
		},
		&cli.DurationFlag{
			Name:  "timeout",
			Usage: "任务超时时间",
		},
		&cli.BoolFlag{
			Name:  "json",
			Usage: "以 JSON 格式输出任务摘要",
		},
		&cli.BoolFlag{
			Name:  "quiet",
			Usage: "仅生成报告文件，终端静默输出",
		},
	}
}

func defaultConfigPath() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	return filepath.Join(home, ".d-eyes", "config.yaml")
}
