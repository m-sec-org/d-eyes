package plugins

import (
	"d-eyes/cmd"
	"d-eyes/pkg/process/controller"
	"fmt"
	"github.com/urfave/cli/v2"
	"os"
	"time"
)

type PluginScanProcess struct {
	Pid 		int
	Path 		string
	Rule 		string
}

func init() {
	cmd.Register(new(PluginScanProcess).InitCommands())
}

func (p *PluginScanProcess) InitCommands() *cli.Command  {
	return &cli.Command{
		Name:    "processcan",
		Aliases: []string{"ps"},
		Usage:   "Command for scanning processes",
		Flags: []cli.Flag{
			&cli.IntFlag{
				Name:        "pid",
				Aliases:     []string{"p"},
				Value:       -1,
				Usage:       "--pid 666 or -p 666 ('-1' means all processes.)",
				Destination: &p.Pid,
			},
			&cli.StringFlag{
				Name:        "rule",
				Aliases:     []string{"r"},
				Usage:       "--rule Ransom.Wannacrypt or -r Ransom.Wannacrypt",
				Destination: &p.Rule,
			},
		},
		Action: p.Run,
	}
}

func (p *PluginScanProcess) Run(c *cli.Context) error  {
	var start = time.Now()
	// todo
	dir, _ := os.Getwd()
	controller.ScanProcess(p.Pid, p.Rule, dir)
	var end = time.Now().Sub(start)
	fmt.Println("Consuming Time: ", end)
	return nil
}