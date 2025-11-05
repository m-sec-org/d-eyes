//go:build linux

package detect

import (
	"fmt"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v4/host"
	"github.com/urfave/cli/v2"

	"github.com/m-sec-org/d-eyes/agent/internal"
	deUtils "github.com/m-sec-org/d-eyes/agent/internal/detect/utils"
	"github.com/m-sec-org/d-eyes/agent/pkg/color"
	"github.com/m-sec-org/d-eyes/agent/pkg/reporting"
)

var SummaryOption *SummaryOptions

func init() {
	SummaryOption = NewDetectPluginSummary()
	internal.RegisterDetectSubcommands(SummaryOption)
}

type SummaryOptions struct {
	internal.BaseOption
}

func NewDetectPluginSummary() *SummaryOptions {
	return &SummaryOptions{
		BaseOption: internal.BaseOption{
			//
			Name:        "export info",
			Author:      "msec",
			Description: "exporting basic host information",
		},
	}
}
func (summary *SummaryOptions) InitCommand() []*cli.Command {
	return []*cli.Command{
		&cli.Command{
			// 导出基本信息
			Name:   "export",
			Usage:  "Command for exporting basic host information",
			Action: summary.Action,
		},
	}
}

func (summary *SummaryOptions) Action(c *cli.Context) error {
	start := time.Now()
	manager := internal.GetReportManager()
	record, notes, err := SaveSummaryBaseInfo(manager)
	if err != nil {
		return err
	}
	manager.PrintSummary(reporting.Summary{
		Command:  "detect export",
		Duration: time.Since(start),
		Outputs:  []reporting.OutputRecord{record},
		Notes:    notes,
		Status:   "完成",
	})
	return nil
}
func SaveSummaryBaseInfo(manager *reporting.Manager) (reporting.OutputRecord, []string, error) {
	file, path, err := manager.CreateFile("detect/export", "summary-base-info", "txt")
	if err != nil {
		return reporting.OutputRecord{}, nil, err
	}
	defer file.Close()

	var builder strings.Builder
	builder.WriteString("HostInfo:\n")
	builder.WriteString(GetBaseInfo())

	users := deUtils.GetLinuxUser()
	builder.WriteString("AllUsers:\n")
	for _, u := range users {
		builder.WriteString("    * ")
		builder.WriteString(u)
		builder.WriteString("\n")
	}

	crontab := GetCronTab()
	builder.WriteString("Os Crontab:\n==============================================================================================\n")
	taskSum := 0
	for _, item := range crontab {
		taskSum++
		builder.WriteString("* task ")
		builder.WriteString(strconv.Itoa(taskSum))
		builder.WriteString("\n")
		builder.WriteString(item)
		builder.WriteString("\n==============================================================================================\n")
	}
	builder.WriteString("InterfaceInfo:\n")
	if _, err := file.WriteString(builder.String()); err != nil {
		return reporting.OutputRecord{}, nil, fmt.Errorf("write summary: %w", err)
	}

	notes := make([]string, 0)
	ifcfg := exec.Command("ifconfig", "-a")
	if output, cmdErr := ifcfg.CombinedOutput(); cmdErr == nil {
		if _, err := file.Write(output); err != nil {
			return reporting.OutputRecord{}, nil, fmt.Errorf("write interface info: %w", err)
		}
	} else {
		notes = append(notes, color.Yellow.Sprintf("ifconfig 执行失败: %v", cmdErr))
	}
	return reporting.OutputRecord{
		Label: "主机概要",
		Path:  path,
	}, notes, nil
}

func GetBaseInfo() string {
	infoStat, _ := host.Info()
	platform := infoStat.Platform + " " + infoStat.PlatformVersion
	OsKernel := infoStat.KernelArch + " " + infoStat.KernelVersion

	current, _ := user.Current()

	baseInfo := ""
	baseInfo += "    * OS VERSION:         " + platform + "\n" +
		"    * KERNEL VERSION:     " + OsKernel + "\n" +
		"    * CURRENT USER:       " + current.Username + "\n"

	return baseInfo
}
