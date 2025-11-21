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

type respondExampleRunner struct{}

func (respondExampleRunner) Run(ctx context.Context, req tasks.TaskRequest) (tasks.TaskResult, error) {
	start := time.Now()
	target := strings.Join(req.Config.Tasks.Respond.Targets, ",")
	if target == "" {
		target = "localhost"
	}
	output := reporting.OutputRecord{Label: "样例输出", Path: "/tmp/respond-example.log"}
	return tasks.TaskResult{
		Outputs: []reporting.OutputRecord{output},
		Risks:   map[string]int{"info": 0},
		Notes: []string{
			fmt.Sprintf("Respond 示例插件扫描目标: %s", target),
			"该输出仅用于演示，非真实检测结果",
		},
		Metadata: map[string]string{
			"plugin":      "respond-example",
			"targets":     target,
			"duration_ms": fmt.Sprintf("%d", time.Since(start).Milliseconds()),
		},
	}, nil
}

func init() {
	internal.RegisterCommand(&cli.Command{
		Name:  "respond-example",
		Usage: "示例响应插件，演示如何注册自定义 Runner",
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
			req.ApplyDefaults("respond-example")
			_, _, err := tasks.ExecuteWithResult(c.Context, "respond-example", respondExampleRunner{}, req, internal.GetReportManager())
			return err
		},
	})
}

func main() {}
