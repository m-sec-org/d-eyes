package plugins

import (
	"fmt"

	"github.com/gookit/color"
	"github.com/urfave/cli/v2"

	"d-eyes/cmd"
)

type PluginUsers struct{}

func init() {
	cmd.Register(new(PluginUsers).InitCommands())
}

func (p *PluginUsers) InitCommands() *cli.Command {
	return &cli.Command{
		Name:   "users",
		Usage:  "Command for displaying all the users on the host",
		Action: p.Run,
	}
}

func (p *PluginUsers) Run(c *cli.Context) error {
	userList := GetUser()
	for _, user := range userList {
		color.Greenp("* ")
		fmt.Println(user)
	}
	return nil
}
