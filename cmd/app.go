package cmd

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

func ParseGlobalOptions() {
	App.Flags = []cli.Flag{
		&cli.BoolFlag{
			Name:        "debug",
			Aliases:     []string{"d"},
			Value:       false,
			Destination: &GlobalOption.Debug,
			Hidden:      true,
		},
	}
}
