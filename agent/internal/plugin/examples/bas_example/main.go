package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/urfave/cli/v2"

	internal "github.com/m-sec-org/d-eyes/agent/internal"
	"github.com/m-sec-org/d-eyes/agent/internal/tasks"
	"github.com/m-sec-org/d-eyes/agent/pkg/reporting"
)

type basExampleRunner struct{}

func (basExampleRunner) Run(ctx context.Context, req tasks.TaskRequest) (tasks.TaskResult, error) {
	start := time.Now()
	steps := []string{"discovery", "exploit", "persist"}
	return tasks.TaskResult{
		Notes: []string{
			"BAS 示例插件：依次执行 discovery/exploit/persist",
			"可用于演示 sandbox metadata 与步骤统计",
		},
		Outputs: []reporting.OutputRecord{
			{Label: "BAS 日志", Path: "/tmp/bas-example.log"},
		},
		Metadata: map[string]string{
			"plugin":      "bas-example",
			"steps":       strings.Join(steps, ","),
			"duration_ms": fmt.Sprintf("%d", time.Since(start).Milliseconds()),
		},
	}, nil
}

func init() {
	internal.RegisterCommand(&cli.Command{
		Name:  "bas-example",
		Usage: "示例 BAS 插件，展示步骤与沙箱 metadata",
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
			req.ApplyDefaults("bas-example")
			_, _, err := tasks.ExecuteWithResult(c.Context, "bas-example", basExampleRunner{}, req, internal.GetReportManager())
			return err
		},
	})
}

func main() {}
