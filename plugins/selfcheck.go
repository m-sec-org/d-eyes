package plugins

import (
	"github.com/urfave/cli/v2"

	"d-eyes/cmd"
	"d-eyes/old/configcheck/check"
)

type PluginSelfCheck struct{}

func init() {
	cmd.Register(new(PluginSelfCheck).InitCommands())
}

func (p *PluginSelfCheck) InitCommands() *cli.Command {
	return &cli.Command{
		Name:    "selfcheck",
		Aliases: []string{"sc"},
		Usage:   "Command for checking some files which may have backdoors",
		Action:  p.Run,
	}
}

func (p *PluginSelfCheck) Run(c *cli.Context) error {
	check.Trigger()
	return nil
}
