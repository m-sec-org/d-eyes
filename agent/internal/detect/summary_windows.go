//go:build windows

package detect

import (
	"fmt"
	"os/user"
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
			// 导出基本信息
			Name:        "export info",
			Author:      "msec",
			Description: "exporting basic host information",
		},
	}
}
func (summary *SummaryOptions) InitCommand() []*cli.Command {
	return []*cli.Command{
		&cli.Command{
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
	builder.WriteString(getBaseInfo())

	users := deUtils.GetWindowsUser()
	builder.WriteString("AllUsers:\n")
	for _, userInfo := range users {
		builder.WriteString("    * ")
		builder.WriteString(userInfo)
		builder.WriteString("\n")
	}

	crontab := GetCronTab()
	builder.WriteString("Os Crontab:\n==============================================================================================\n")
	for _, item := range crontab {
		builder.WriteString("*NAME:        ")
		builder.WriteString(item.Name)
		builder.WriteString("\n*COMMAND:     ")
		builder.WriteString(item.Command)
		builder.WriteString("\n*ARG:         ")
		builder.WriteString(item.Arg)
		builder.WriteString("\n*USER:        ")
		builder.WriteString(item.User)
		builder.WriteString("\n*RULE:        ")
		builder.WriteString(item.Rule)
		builder.WriteString("\n*DESCRIPTION: ")
		builder.WriteString(item.Description)
		builder.WriteString("\n==============================================================================================\n")
	}
	builder.WriteString("InterfaceInfo:\n")
	if _, err := file.WriteString(builder.String()); err != nil {
		return reporting.OutputRecord{}, nil, fmt.Errorf("write summary: %w", err)
	}

	notes := make([]string, 0)
	ifaceNotes, err := writeInterfaceInfo(file)
	if err != nil {
		return reporting.OutputRecord{}, nil, fmt.Errorf("write interface info: %w", err)
	}
	for _, note := range ifaceNotes {
		notes = append(notes, color.Yellow.Sprintf("%s", note))
	}

	return reporting.OutputRecord{
		Label: "主机概要",
		Path:  path,
	}, notes, nil
}

func getBaseInfo() string {
	infoStat, _ := host.Info()
	platform := infoStat.Platform + " " + infoStat.PlatformVersion
	OsKernel := infoStat.KernelArch + " " + infoStat.KernelVersion

	userInfo, _ := user.Current()

	baseInfo := ""
	baseInfo += "    * OS VERSION:         " + platform + "\n" +
		"    * KERNEL VERSION:     " + OsKernel + "\n" +
		"    * CURRENT USER:       " + userInfo.Username + "\n"

	return baseInfo
}
