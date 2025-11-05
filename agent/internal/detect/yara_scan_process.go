//go:build linux || windows

package detect

import (
	"fmt"
	"os"

	"github.com/shirou/gopsutil/v4/process"
	"github.com/urfave/cli/v2"

	"github.com/m-sec-org/d-eyes/agent/internal"
	"github.com/m-sec-org/d-eyes/agent/internal/detect/engine"
	"github.com/m-sec-org/d-eyes/agent/internal/detect/scoring"
	"github.com/m-sec-org/d-eyes/agent/pkg/color"
)

var YaraProcessScanOption *YaraProcessScanOptions

func init() {
	YaraProcessScanOption = NewDetectPluginYaraScan()
	internal.RegisterDetectSubcommands(YaraProcessScanOption)
}

type YaraProcessScanOptions struct {
	// 要扫描的pid
	Pid int
	// 自定义rule
	RulePath string
	internal.BaseOption
}

func NewDetectPluginYaraScan() *YaraProcessScanOptions {
	return &YaraProcessScanOptions{
		RulePath: "",
		BaseOption: internal.BaseOption{
			Name:        "yara process scan",
			Author:      "msec",
			Description: "msec community love to develop, yara scan system process plug-in",
		},
	}
}

func (scan *YaraProcessScanOptions) InitCommand() []*cli.Command {
	return []*cli.Command{
		{
			// 进程扫描，待完成
			Name: "processcan",
			// 使用yara规则扫描指定的文件或文件夹
			Usage:   "Command for scanning processes",
			Aliases: []string{"ps"},
			Action:  scan.Action,
			Flags: []cli.Flag{
				&cli.IntFlag{
					Name:        "pid",
					Aliases:     []string{"p"},
					Value:       -1,
					Usage:       "--pid 666 or -p 666 ('-1' means all processes.)",
					Destination: &YaraProcessScanOption.Pid,
				},
				&cli.StringFlag{
					Name:        "rule",
					Aliases:     []string{"r"},
					Usage:       "Specifies the rule file or directory (defaults to embedded set)",
					Destination: &YaraProcessScanOption.RulePath,
				},
			},
		},
	}
}
func (scan *YaraProcessScanOptions) Action(_ *cli.Context) error {
	bundle, err := loadRuleBundle(scan.RulePath)
	if err != nil {
		return err
	}
	fmt.Printf("Loaded %d rules (engine=%s version=%s)\n", bundle.RuleCount(), bundle.Name(), bundle.Version())

	targets, err := scan.resolveTargets()
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		fmt.Println(color.Yellow.Sprint("No processes selected for scanning."))
		return nil
	}

	var count int
	for _, proc := range targets {
		exe, err := proc.Exe()
		if err != nil || exe == "" {
			continue
		}
		data, err := os.ReadFile(exe)
		if err != nil {
			continue
		}
		matches, err := bundle.Scan(data, engine.ScanOptions{FilePath: exe})
		if err != nil {
			continue
		}
		if len(matches) == 0 {
			continue
		}
		count++
		fmt.Println(color.Cyan.Sprintf("Process PID=%d CMD=%s", proc.Pid, exe))
		for i, match := range matches {
			res := DetectionResult{
				RuleName:      match.RuleName,
				Description:   match.Description,
				FilePath:      exe,
				Tags:          match.Tags,
				MatchedString: extractStringIDs(match.Strings),
			}
			res.Risk = scoring.Calculate(match.RuleName, match.ScoreHints, match.Tags)
			res.Remediation = scoring.ResolveRemediation(match.RuleName, match.Tags)
			printDetection(res, i+1)
		}
		fmt.Println()
	}
	if count == 0 {
		fmt.Println(color.Green.Sprint("No suspicious process binaries detected."))
	}
	return nil
}

func (scan *YaraProcessScanOptions) resolveTargets() ([]*process.Process, error) {
	if scan.Pid > 0 {
		proc, err := process.NewProcess(int32(scan.Pid))
		if err != nil {
			return nil, err
		}
		return []*process.Process{proc}, nil
	}
	return process.Processes()
}
