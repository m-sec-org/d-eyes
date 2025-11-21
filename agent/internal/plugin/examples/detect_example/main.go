package main

import (
	"context"
	"fmt"
	"time"

	"github.com/urfave/cli/v2"

	internal "github.com/m-sec-org/d-eyes/agent/internal"
	"github.com/m-sec-org/d-eyes/agent/internal/tasks"
	"github.com/m-sec-org/d-eyes/agent/pkg/reporting"
)

type detectExampleRunner struct{}

func (detectExampleRunner) Run(ctx context.Context, req tasks.TaskRequest) (tasks.TaskResult, error) {
	start := time.Now()
	return tasks.TaskResult{
		Risks: map[string]int{"critical": 1, "high": 2},
		Notes: []string{
			"检测示例：模拟发现 1 个关键、2 个高危风险",
			"该插件仅演示如何返回风险计数与输出",
		},
		Outputs: []reporting.OutputRecord{
			{Label: "检测报告", Path: "/tmp/detect-example.json"},
		},
		Metadata: map[string]string{
			"plugin":          "detect-example",
			"scanned_targets": fmt.Sprintf("%v", req.Config.Tasks.Respond.Targets),
			"duration_ms":     fmt.Sprintf("%d", time.Since(start).Milliseconds()),
		},
	}, nil
}

func init() {
	internal.RegisterCommand(&cli.Command{
		Name:  "detect-example",
		Usage: "示例检测插件，演示如何返回风险与报告",
		Action: func(c *cli.Context) error {
			cfg := internal.GetGlobalConfig()
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
			req.ApplyDefaults("detect-example")
			_, _, err := tasks.ExecuteWithResult(c.Context, "detect-example", detectExampleRunner{}, req, internal.GetReportManager())
			return err
		},
	})
}

func main() {}
