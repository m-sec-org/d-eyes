package tasks

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/m-sec-org/d-eyes/agent/pkg/reporting"
)

type RespondModuleSelector func(profile string) []respondModule

type respondRunner struct {
	selectModules RespondModuleSelector
}

func RespondRunner() TaskRunner {
	return RespondRunnerWithSelector(nil)
}

func RespondRunnerWithSelector(selector RespondModuleSelector) TaskRunner {
	if selector == nil {
		selector = selectRespondProfile
	}
	return &respondRunner{selectModules: selector}
}

func (r *respondRunner) Run(ctx context.Context, req TaskRequest) (TaskResult, error) {
	if req.Manager == nil {
		return TaskResult{}, errors.New("report manager missing")
	}
	selector := r.selectModules
	if selector == nil {
		selector = selectRespondProfile
	}
	profile := strings.ToLower(req.Profile)
	modules := selector(profile)
	if len(modules) == 0 {
		modules = selector("default")
	}
	outputs := make([]reporting.OutputRecord, 0)
	notes := make([]string, 0)
	risks := make(map[string]int)

	if req.Debugger != nil {
		req.Debugger.PhaseStart("respond", "modules", fmt.Sprintf("total=%d", len(modules)))
	}
	for idx, module := range modules {
		select {
		case <-ctx.Done():
			notes = append(notes, "任务被取消")
			if req.Debugger != nil {
				req.Debugger.Notice("respond", "任务被取消")
				req.Debugger.PhaseEnd("respond", "cancelled")
			}
			return TaskResult{Outputs: outputs, Risks: risks, Notes: notes}, ctx.Err()
		default:
		}
		if req.Debugger != nil {
			req.Debugger.Progress("respond", idx, len(modules), fmt.Sprintf("下一个: %s", module.Name))
			label := fmt.Sprintf("%s (%d/%d)", module.Name, idx+1, len(modules))
			req.Debugger.PhaseStart("respond."+module.Name, label, fmt.Sprintf("profile=%s", req.Profile))
		}
		res, err := module.Run(ctx, req)
		if err != nil {
			notes = append(notes, fmt.Sprintf("%s 执行失败: %v", module.Name, err))
			if req.Debugger != nil {
				req.Debugger.Error("respond."+module.Name, err.Error())
			}
			continue
		}
		outputs = append(outputs, res.Outputs...)
		notes = append(notes, res.Notes...)
		accumulateRisk(risks, res.Risks)
		if req.Debugger != nil {
			for _, out := range res.Outputs {
				req.Debugger.Artifact(module.Name, out.Path)
			}
			if len(res.Risks) > 0 {
				req.Debugger.Notice("respond."+module.Name, fmt.Sprintf("风险: %+v", res.Risks))
			}
			if len(res.Notes) > 0 {
				req.Debugger.Notice("respond."+module.Name, strings.Join(res.Notes, "; "))
			}
			req.Debugger.Progress("respond", idx+1, len(modules), module.Name)
			req.Debugger.PhaseEnd("respond."+module.Name, "done")
		}
	}
	if req.Debugger != nil {
		req.Debugger.PhaseEnd("respond", "complete")
	}
	metadata := cloneMetadata(req.Metadata)
	return TaskResult{Outputs: outputs, Risks: risks, Notes: notes, Metadata: metadata}, nil
}

type respondModule struct {
	Name string
	Run  func(context.Context, TaskRequest) (moduleResult, error)
}

func selectRespondProfile(name string) []respondModule {
	defaultModules := []respondModule{
		{Name: "HostSummary", Run: runHostSummary},
		{Name: "NetworkConnections", Run: runNetworkAnalysis},
	}
	switch name {
	case "quick", "default":
		return defaultModules
	case "ransomware":
		return []respondModule{
			{Name: "HostSummary", Run: runHostSummary},
			{Name: "FileScan", Run: runFileScan},
			{Name: "NetworkConnections", Run: runNetworkAnalysis},
		}
	case "persistence":
		return []respondModule{
			{Name: "HostSummary", Run: runHostSummary},
			{Name: "NetworkConnections", Run: runNetworkAnalysis},
			{Name: "UserEnumeration", Run: runUserInspection},
		}
	default:
		return defaultModules
	}
}
