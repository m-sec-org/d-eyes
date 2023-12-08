package plugins

import (
	"d-eyes/cmd"
	"d-eyes/pkg/windows_log"
	"github.com/urfave/cli/v2"
)

type PluginWindowsLogs struct {
	LogType		string
	Size 		int
	Ignore 		string
}

func init() {
	cmd.Register(new(PluginWindowsLogs).InitCommands())
}

func (p *PluginWindowsLogs) InitCommands() *cli.Command {
	return &cli.Command{
		Name: "logs",
		Usage: "Command for logs of Application, System and Security Information",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:			"log_type",
				Aliases: 		[]string{"lt"},
				Value: 			"system",
				Usage:			"--log_type system or -lt system (Only for logs options:[system,application,security])",
				Destination: 	&p.LogType,
			},
			&cli.StringFlag{
				Name: 			"ignore",
				Aliases: 		[]string{"i"},
				Value: 			"1h",
				Usage: 			"--ignore 1h or -i 1h (Only for logs ignore before options:[1h,12h,24h,week,month])",
				Destination: 	&p.Ignore,
			},
			&cli.IntFlag{
				Name: 			"size",
				Aliases: 		[]string{"s"},
				Value: 			200,
				Usage: 			"--size 200 or -s 200 (Only for logs)",
				Destination: 	&p.Size,
			},
		},
		Action: p.Run,
	}
}

func (p *PluginWindowsLogs) Run(c *cli.Context) error {
	windows_log.DisplayWindowsLogs(p.LogType, p.Ignore, p.Size)
	return nil
}