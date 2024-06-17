package internal

import (
	"github.com/urfave/cli/v2"
)

var App *cli.App

func init() {
	App = cli.NewApp()
	App.Name = "d-eyes"
	App.Usage = "The Eyes of Darkness from Nsfocus spy on everything."
	App.Commands = make([]*cli.Command, 0)
}

// RegisterCommand 注册插件
func RegisterCommand(c *cli.Command) {
	if c == nil {
		panic("plugin: Register plugin is nil")
	}
	App.Commands = append(App.Commands, c)
}
