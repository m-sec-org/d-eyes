//go:build linux

package detect

import (
	"fmt"
	"github.com/m-sec-org/d-eyes/internal"
	autoruns "github.com/m-sec-org/d-eyes/internal/detect/utils"
	"github.com/m-sec-org/d-eyes/internal/utils"
	"github.com/m-sec-org/d-eyes/pkg/color"
	"github.com/olekukonko/tablewriter"
	"github.com/urfave/cli/v2"
	"os"
)

var AutorunOption *AutorunOptions

type AutorunOptions struct {
	internal.BaseOption
}

func init() {
	AutorunOption = NewDetectPluginAutorun()
	internal.RegisterDetectSubcommands(AutorunOption)

}
func NewDetectPluginAutorun() *AutorunOptions {
	return &AutorunOptions{
		internal.BaseOption{
			// 自动启动
			Name:        "check  Autorun",
			Author:      "msec",
			Description: "Command for displaying all the autorun on the host",
		},
	}
}
func (autorun *AutorunOptions) InitCommand() []*cli.Command {
	return []*cli.Command{{
		Name:  "autorun",
		Usage: "Command for displaying all the autorun on the host",
		// 这是执行命令只会激活的函数
		Action: autorun.Action,
	}}
}
func (autorun *AutorunOptions) Action(_ *cli.Context) error {
	fmt.Println(color.Green.Sprint("Autorun:"))
	callDisplayAutorun()
	return nil
}

type AutoRuns struct {
	AutoRuns []*autoruns.Autorun
}

func GetAutorun() *AutoRuns {
	ret := autoruns.Autoruns()
	return &AutoRuns{AutoRuns: ret}
}

func displayAutorun(autoRuns *AutoRuns) {
	data := make([][]string, 0)
	for _, autorun := range autoRuns.AutoRuns {
		autorunData := make([]string, 0)

		path := utils.StringNewLine(autorun.ImagePath, 25)
		autorunData = append(autorunData, autorun.Type, autorun.ImageName, autorun.Arguments, path)
		data = append(data, autorunData)
	}

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Type", "ImageName", "Arguments", "Path"})
	table.SetHeaderAlignment(tablewriter.ALIGN_CENTER)
	table.SetBorder(true)
	table.SetRowLine(true)
	table.SetAutoMergeCells(true)
	table.AppendBulk(data)
	table.SetCaption(true, "Autorun list")
	table.Render()
}

func callDisplayAutorun() {
	autorun := GetAutorun()
	displayAutorun(autorun)
}
