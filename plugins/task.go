package plugins

import (
	"github.com/urfave/cli/v2"

	"d-eyes/cmd"
)

type PluginTask struct{}

func init() {
	cmd.Register(new(PluginTask).InitCommands())
}

func (p *PluginTask) InitCommands() *cli.Command {
	return &cli.Command{
		Name:   "task",
		Usage:  "Command for displaying all the tasks on the host",
		Action: p.Run,
	}
}

func (p *PluginTask) Run(c *cli.Context) error {
	DisplayPlanTask()
	return nil
}
