package python

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/m-sec-org/d-eyes/internal"
	"github.com/m-sec-org/d-eyes/internal/constant"
	"github.com/m-sec-org/d-eyes/internal/sbom"
	"github.com/m-sec-org/d-eyes/pkg/color"
	"github.com/urfave/cli/v2"
	"os"
	"os/exec"
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
func (conda *Conda) Action(c *cli.Context) error {

	cmd := exec.Command("conda", "list")

	var out bytes.Buffer
	cmd.Stdout = &out

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {

		var exitErr *exec.Error
		var exitError *exec.ExitError
		if errors.As(err, &exitError) {
			fmt.Println(color.Magenta.Sprint("请检查pip命令是否存在"))
			os.Exit(1)
		} else if errors.As(err, &exitErr) {
			fmt.Println(color.Magenta.Sprintf("执行错误,%s", err.Error()))
			os.Exit(1)
		} else {
			fmt.Printf("未知错误")
			os.Exit(1)
		}
		return nil
	}
	conda.Parse(out.String())
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
