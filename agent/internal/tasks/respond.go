package tasks

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/m-sec-org/d-eyes/agent/pkg/reporting"
)

type respondRunner struct{}

func RespondRunner() TaskRunner {
	return &respondRunner{}
}

func (r *respondRunner) Run(ctx context.Context, req TaskRequest) (TaskResult, error) {
	if req.Manager == nil {
		return TaskResult{}, errors.New("report manager missing")
	}
	profile := strings.ToLower(req.Profile)
	modules := selectRespondProfile(profile)
	if len(modules) == 0 {
		modules = selectRespondProfile("default")
	}
	outputs := make([]reporting.OutputRecord, 0)
	notes := make([]string, 0)
	risks := make(map[string]int)

	for _, module := range modules {
		select {
		case <-ctx.Done():
			notes = append(notes, "任务被取消")
			return TaskResult{Outputs: outputs, Risks: risks, Notes: notes}, ctx.Err()
		default:
		}
		res, err := module.Run(ctx, req)
		if err != nil {
			notes = append(notes, fmt.Sprintf("%s 执行失败: %v", module.Name, err))
			continue
		}
		outputs = append(outputs, res.Outputs...)
		notes = append(notes, res.Notes...)
		accumulateRisk(risks, res.Risks)
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
