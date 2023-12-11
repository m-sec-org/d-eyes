package plugins

import (
	"d-eyes/cmd"
	"github.com/urfave/cli/v2"
)

type PluginFileScan struct {
	Path   string
	Rule   string
	Thread int
}

func init() {
	//cmd.Register("filescan", &PluginFileScan{})
}

func (f *PluginFileScan) InitCommands() *cli.Command {
	return &cli.Command{
		Name:    "filescan",
		Aliases: []string{"fs"},
		Usage:   "Command for scanning filesystem",
		Flags: []cli.Flag{
			cmd.BuildPathFlag(&f.Path, "/", true),
			cmd.BuildRuleFlag(&f.Rule, "", false),
			cmd.BuildThreadFlag(&f.Thread, 5, false),
		},
		Action: f.Run,
	}
}

func (f *PluginFileScan) Run(c *cli.Context) error {
		/*var paths []string
		var r []output.Result
		paths = strings.Split(f.Path, ",")
		var start = time.Now()
		var sum = 0

		if f.Rule == "" {
			yaraRule := "./yaraRules"
			rules, err := yaraobj.LoadAllYaraRules(yaraRule)
			if err != nil {
				color.Redln("LoadCompiledRules goes error !!!")
				color.Redln("GetRules err: ", err)
				os.Exit(1)
			}
			for _, path := range paths {
				files := filedetection.StartFileScan(path, rules, f.Thread, &r)
				sum += files
			}
		} else {
			yaraRule := "./yaraRules/" + f.Rule + ".yar"
			_, err := os.Lstat(yaraRule)
			if err != nil {
				color.Redln("There is no such rule yet !!!")
				os.Exit(1)
			}
			rules, err := yaraobj.LoadSingleYaraRule(yaraRule)
			if err != nil {
				color.Redln("GetRules err: ", err)
				os.Exit(1)
			}
			for _, path := range paths {
				files := filedetection.StartFileScan(path, rules, f.Thread, &r)
				sum += files
			}
		}

		if len(r) > 0 {
			length := len(r)
			categories := map[string]string{
				"A1": "Risk Description", "B1": "Risk File Path",
			}
			var values = make(map[string]string)
			vulsumTmp := 0
			for i := 0; i < length; i++ {
				vulsumTmp++
				color.Error.Println("[ Risk ", vulsumTmp, " ]")
				fmt.Print("Risk Description: ")
				color.Warn.Println(r[i].Risk)
				fmt.Println("Risk File Path: ")
				color.Warn.Println(r[i].RiskPath)
				//set excel values
				excelValuetmpA := "A" + strconv.Itoa(vulsumTmp+1)
				excelValuetmpB := "B" + strconv.Itoa(vulsumTmp+1)
				values[excelValuetmpA] = r[i].Risk
				values[excelValuetmpB] = r[i].RiskPath
			}
			//output to a excel
			f := excelize.NewFile()
			f.SetColWidth("Sheet1", "A", "B", 50)
			for k, v := range categories {
				f.SetCellValue("Sheet1", k, v)
			}
			for k, v := range values {
				f.SetCellValue("Sheet1", k, v)
			}
			style, err := f.NewStyle(
				&excelize.Style{
					Font: &excelize.Font{
						Bold:  true,
						Size:  11,
						Color: "e83723",
					},
				},
			)
			if err != nil {
				fmt.Println(err)
			}
			f.SetCellStyle("Sheet1", "A1", "A1", style)
			f.SetCellStyle("Sheet1", "B1", "B1", style)
			// save the result to Deyes.xlsx
			if err := f.SaveAs("D-Eyes.xlsx"); err != nil {
				fmt.Println(err)
			}
		} else {
			fmt.Println("\nNo suspicious files found. Your computer is safe with the rules you choose.")
		}
		var end = time.Now().Sub(start)
		fmt.Println("Consuming Time: ", end, "  Number of scanned files: ", sum)*/

	return nil
}
