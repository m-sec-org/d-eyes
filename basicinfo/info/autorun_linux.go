package info

import (
	"os"

	"github.com/olekukonko/tablewriter"

	autoruns "d-eyes/basicinfo/utils"
)

type AutoRuns struct {
	AutoRuns []*autoruns.Autorun
}

func GetAutoruns() *AutoRuns {
	ret := autoruns.Autoruns()
	return &AutoRuns{AutoRuns: ret}
}

func DisplayAutoruns(autoRuns *AutoRuns) {
	data := make([][]string, 0)
	for _, autorun := range autoRuns.AutoRuns {
		autorunData := make([]string, 0)

		path := StringNewLine(autorun.ImagePath, 25)
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
	table.SetCaption(true, "Autoruns list")
	table.Render()
}

func StringNewLine(str string, ln uint8) string {
	var sub_str string
	res_str := ""
	for {
		if len(str) < int(ln) {
			res_str += str
			break
		}
		sub_str = str[0:ln]
		str = str[ln:]
		res_str += sub_str + "\n"
	}
	return res_str
}

func CallDisplayAutoruns() {
	autoruns := GetAutoruns()
	DisplayAutoruns(autoruns)
}
