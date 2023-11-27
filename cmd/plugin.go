package cmd

import (
	"github.com/urfave/cli/v2"
)

// Plugin 插件
type Plugin interface {
	InitCommands() *cli.Command
	Run(c *cli.Context) error
}

var plugins = make(map[string]struct{})

// Register 注册插件
func Register(c *cli.Command) {
	if c == nil {
		panic("plugin: Register plugin is nil")
	}
	if _, ok := plugins[c.Name]; ok {
		panic("plugin: Register called twice for plugin " + c.Name)
	}
	App.Commands = append(App.Commands, c)
	plugins[c.Name] = struct{}{}
}
