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

type Pip struct {
}

var PipSbu *Pip

func init() {
	PipSbu = NewPluginPip()
	internal.RegisterSbomSub(PipSbu)

}
func NewPluginPip() *Pip {
	return &Pip{}
}
func (pip *Pip) InitCommand() *cli.Command {
	return &cli.Command{
		Name:   "pip",
		Usage:  "Parses the package of pip in the environment variable and generates the sbom boring list",
		Action: pip.Action,
	}
}

func runPipList(ctx context.Context) (cmdexec.Result, error) {
	return cmdexec.Run(ctx, cmdexec.Request{
		Command:    "pip",
		Args:       []string{"list", "--format=freeze"},
		Identifier: "sbom.python pip list",
	})
}

func (pip *Pip) Action(c *cli.Context) error {

	res, err := runPipList(c.Context)
	if err != nil {
		lower := strings.ToLower(err.Error())
		if strings.Contains(lower, "command denied") {
			fmt.Println(color.Magenta.Sprint("pip 命令被策略禁止，请在配置中允许执行"))
		} else if strings.Contains(lower, "executable file not found") || strings.Contains(lower, "not found") {
			fmt.Println(color.Magenta.Sprint("请检查pip命令是否存在"))
		} else {
			fmt.Println(color.Magenta.Sprintf("执行错误,%s", err.Error()))
		}
		if stderr := strings.TrimSpace(res.Stderr); stderr != "" {
			fmt.Println(color.Magenta.Sprintf("%s", stderr))
		}
		os.Exit(1)
		return nil
	}
	pip.Parse(res.Stdout)
	return nil
}

func (pip *Pip) Parse(input string) {
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
		parts := strings.SplitN(line, "==", 2)
		if len(parts) != 2 {
			continue
		}
		component := sbom.Component{
			Name:    parts[0],
			Version: strings.Trim(parts[1], "\r"),
		}
		componentList = append(componentList, &component)
	}
	resTemp.Component = componentList
	res = append(res, resTemp)
	internal.ResultFunc(res)
}
