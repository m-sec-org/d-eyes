package tasks

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/m-sec-org/d-eyes/agent/pkg/reporting"
)

type auditRunner struct{}

func AuditRunner() TaskRunner {
	return &auditRunner{}
}

func (a *auditRunner) Run(ctx context.Context, req TaskRequest) (TaskResult, error) {
	if req.Manager == nil {
		return TaskResult{}, errors.New("report manager missing")
	}
	outputs := make([]reporting.OutputRecord, 0)
	notes := make([]string, 0)
	risks := make(map[string]int)

	// 基线检查
	baselineReq := req
	baselineReq.Name = req.Name + "-baseline"
	baselineReq.Profile = strings.TrimSpace(req.Profile)
	if baselineReq.Profile == "" {
		baselineReq.Profile = "compliance"
	}
	baselineReq.Flags = cloneFlags(req.Flags)
	if _, ok := baselineReq.Flags["scope"]; !ok {
		baselineReq.Flags["scope"] = "all"
	}
	res, err := (&baselineRunner{}).Run(ctx, baselineReq)
	if err != nil {
		notes = append(notes, fmt.Sprintf("baseline 执行失败: %v", err))
	} else {
		outputs = append(outputs, res.Outputs...)
		notes = append(notes, res.Notes...)
		accumulateRisk(risks, res.Risks)
	}

	// 主机概要
	hostRes, err := runHostSummary(ctx, req)
	if err != nil {
		notes = append(notes, fmt.Sprintf("host summary 失败: %v", err))
	} else {
		outputs = append(outputs, hostRes.Outputs...)
		accumulateRisk(risks, hostRes.Risks)
	}

	// 用户会话
	userRes, err := runUserInspection(ctx, req)
	if err != nil {
		notes = append(notes, fmt.Sprintf("user inspection 失败: %v", err))
	} else {
		outputs = append(outputs, userRes.Outputs...)
		accumulateRisk(risks, userRes.Risks)
	}

	// 生成汇总 JSON
	if summaryRecord, err := writeAuditSummary(req, outputs, risks, notes); err != nil {
		notes = append(notes, fmt.Sprintf("汇总报告写入失败: %v", err))
	} else if summaryRecord.Path != "" {
		outputs = append(outputs, summaryRecord)
	}

	return TaskResult{
		Outputs: outputs,
		Risks:   risks,
		Notes:   notes,
	}, nil
}

func writeAuditSummary(req TaskRequest, outputs []reporting.OutputRecord, risks map[string]int, notes []string) (reporting.OutputRecord, error) {
	file, path, err := req.Manager.CreateFile("audit", req.Name+"-summary", "json")
	if err != nil {
		return reporting.OutputRecord{}, err
	}
	defer file.Close()
	summary := struct {
		Profile string                   `json:"profile"`
		Outputs []reporting.OutputRecord `json:"outputs"`
		Risks   map[string]int           `json:"risks"`
		Notes   []string                 `json:"notes"`
	}{
		Profile: req.Profile,
		Outputs: outputs,
		Risks:   risks,
		Notes:   notes,
	}
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(summary); err != nil {
		return reporting.OutputRecord{}, err
	}
	return reporting.OutputRecord{Label: "审计汇总", Path: path}, nil
}

func cloneFlags(source map[string]any) map[string]any {
	clone := make(map[string]any)
	for k, v := range source {
		clone[k] = v
	}
	return clone
}
