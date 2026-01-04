package python

import (
	"context"
	"fmt"

	"github.com/m-sec-org/d-eyes/agent/internal"
	"github.com/m-sec-org/d-eyes/agent/internal/cmdexec"
	"github.com/m-sec-org/d-eyes/agent/internal/constant"
	"github.com/m-sec-org/d-eyes/agent/internal/sbom"
	"github.com/m-sec-org/d-eyes/agent/pkg/color"
	"github.com/urfave/cli/v2"
	"os"
	"strings"
)

type Conda struct {
}

var CondaSbu *Conda

func init() {
	CondaSbu = NewPluginConda()
	internal.RegisterSbomSub(CondaSbu)

}
func NewPluginConda() *Conda {
	return &Conda{}
}
func (conda *Conda) InitCommand() *cli.Command {
	return &cli.Command{
		Name:   "conda",
		Usage:  "Parses the package of conda in the environment variable and generates the sbom boring list",
		Action: conda.Action,
	}
}

func runCondaList(ctx context.Context) (cmdexec.Result, error) {
	return cmdexec.Run(ctx, cmdexec.Request{
		Command:    "conda",
		Args:       []string{"list"},
		Identifier: "sbom.python conda list",
	})
}

func (conda *Conda) Action(c *cli.Context) error {

	res, err := runCondaList(c.Context)
	if err != nil {

		lower := strings.ToLower(err.Error())
		if strings.Contains(lower, "command denied") {
			fmt.Println(color.Magenta.Sprint("conda 命令被策略禁止，请在配置中允许执行"))
		} else if strings.Contains(lower, "executable file not found") || strings.Contains(lower, "not found") {
			fmt.Println(color.Magenta.Sprint("请检查conda命令是否存在"))
		} else {
			fmt.Println(color.Magenta.Sprintf("执行错误,%s", err.Error()))
		}
		if stderr := strings.TrimSpace(res.Stderr); stderr != "" {
			fmt.Println(color.Magenta.Sprintf("%s", stderr))
		}
		os.Exit(1)
		return nil
	}
	conda.Parse(res.Stdout)
	return nil
}
func (conda *Conda) Parse(input string) {
	internal.SbomOption.ParseSbomOption(true)
	var res []sbom.ResultComponent
	var resTemp sbom.ResultComponent
	resTemp.LanguageType = constant.Python
	var componentList []*sbom.Component
	lines := strings.Split(input, "\n")
	for _, line := range lines {
		if line == "" {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		component := sbom.Component{
			Name:    parts[0],
			Version: parts[1],
		}
		componentList = append(componentList, &component)
	}
	resTemp.Component = componentList
	res = append(res, resTemp)
	internal.ResultFunc(res)
}
