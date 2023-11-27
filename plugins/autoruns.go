package plugins

import (
	"os"

	"github.com/botherder/go-autoruns"
	"github.com/olekukonko/tablewriter"
	"github.com/urfave/cli/v2"

	"d-eyes/cmd"
)

type PluginAutoRuns struct{}

func init() {
	cmd.Register(new(PluginAutoRuns).InitCommands())
}

func (p *PluginAutoRuns) InitCommands() *cli.Command {
	return &cli.Command{
		Name:    "autoruns",
		Usage:   "Command for displaying all the autoruns on the host",
		Aliases: []string{"ar"},
		Action:  p.Run,
	}
}

func (p *PluginAutoRuns) Run(c *cli.Context) error {
	ar := GetAutoruns()
	DisplayAutoruns(ar)
	return nil
}

func GetAutoruns() []*autoruns.Autorun {
	ret := autoruns.Autoruns()
	return ret
}

func DisplayAutoruns(autoRuns []*autoruns.Autorun) {
	data := make([][]string, 0)
	for _, autorun := range autoRuns {
		autorunData := make([]string, 0)
		path := StringNewLine(autorun.LaunchString, 100)
		autorunData = append(autorunData, autorun.Type, autorun.ImageName, path)
		data = append(data, autorunData)
	}

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Type", "ImageName", "LaunchCommand"})
	table.SetHeaderAlignment(tablewriter.ALIGN_CENTER)
	table.SetBorder(true)
	table.SetRowLine(true)
	table.SetAutoMergeCells(true)
	table.AppendBulk(data)
	table.SetCaption(true, "Autoruns list")
	table.Render()
}
