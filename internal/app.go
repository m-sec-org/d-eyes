package internal

import (
	"fmt"

	"github.com/urfave/cli/v2"

	"github.com/m-sec-org/d-eyes/pkg/color"
)

var App *cli.App

func init() {
	App = cli.NewApp()
	App.Name = "d-eyes"
	App.Usage = "The Eyes of Darkness from Nsfocus spy on everything."
	App.Commands = []*cli.Command{
		{
			Name:    "version",
			Aliases: []string{"v"},
			Usage:   "Show the version of d-eyes",
			Action: func(c *cli.Context) error {
				fmt.Println(color.Green.Sprint("v1.3.0"))
				return nil
			},
		},
	}
}

// RegisterCommand 注册插件
func RegisterCommand(c *cli.Command) {
	if c == nil {
		panic("plugin: Register plugin is nil")
	}
	App.Commands = append(App.Commands, c)
}
