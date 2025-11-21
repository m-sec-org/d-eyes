package tasks

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/m-sec-org/d-eyes/agent/internal/model"
	"github.com/m-sec-org/d-eyes/agent/internal/telemetry"
	"github.com/m-sec-org/d-eyes/agent/pkg/config"
	"github.com/m-sec-org/d-eyes/agent/pkg/exit"
	"github.com/m-sec-org/d-eyes/agent/pkg/reporting"
)

// ErrNotImplemented 用于标识任务尚未实现
var ErrNotImplemented = errors.New("task not implemented")

// Execute 执行任务并输出统一摘要
func Execute(ctx context.Context, name string, runner TaskRunner, req TaskRequest, manager *reporting.Manager) error {
	_, _, err := ExecuteWithResult(ctx, name, runner, req, manager)
	return err
}

// ExecuteWithResult 运行任务并返回结果与摘要，供嵌入式调用场景复用。
func ExecuteWithResult(ctx context.Context, name string, runner TaskRunner, req TaskRequest, manager *reporting.Manager) (reporting.Summary, TaskResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if runner == nil {
		return reporting.Summary{}, TaskResult{}, errors.New("task runner is nil")
	}
	if manager == nil {
		manager = reporting.NewManager(config.Default())
	}
	req.Manager = manager
	start := time.Now()
	tracker := telemetry.NewTaskResourceTracker()
	result, err := runner.Run(ctx, req)
	resourceStats := tracker.Snapshot()
	result.Metadata = telemetry.AppendTaskResourceMetadata(result.Metadata, resourceStats)

	status := "完成"
	switch {
	case errors.Is(err, ErrNotImplemented):
		status = "未完成"
	case err != nil:
		status = "失败"
	}

	var policyErr error
	if err == nil {
		policyErr = evaluatePolicy(req.Config.Policy, result.Risks)
		if policyErr != nil {
			status = "警告"
		}
	}
	summary := reporting.Summary{
		Command:  name,
		Duration: time.Since(start),
		Outputs:  result.Outputs,
		Risks:    result.Risks,
		Notes:    result.Notes,
		Status:   status,
	}

	if req.JSONOutput {
		jsonSummary := struct {
			Command  string                   `json:"command"`
			Status   string                   `json:"status"`
			Duration float64                  `json:"duration_seconds"`
			Outputs  []reporting.OutputRecord `json:"outputs"`
			Risks    map[string]int           `json:"risks"`
			Notes    []string                 `json:"notes"`
		}{
			Command:  name,
			Status:   status,
			Duration: summary.Duration.Seconds(),
			Outputs:  summary.Outputs,
			Risks:    summary.Risks,
			Notes:    summary.Notes,
		}
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		_ = encoder.Encode(jsonSummary)
	}

	if !req.Quiet && len(req.Notices) > 0 {
		for _, notice := range req.Notices {
			fmt.Fprintf(os.Stderr, "[NOTICE] %s\n", notice)
		}
	}
	if !req.Quiet {
		manager.PrintSummary(summary)
	}
	if err != nil {
		code := 2
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			code = 3
		}
		return summary, result, exit.New(code, err)
	}
	if policyErr != nil {
		return summary, result, exit.New(1, fmt.Errorf("policy violation: %w", policyErr))
	}
	return summary, result, nil
}

// ToExecutionResult 将执行结果转换为共享模型结构，便于与 Server 统一。
func ToExecutionResult(summary reporting.Summary, result TaskResult, err error) model.ExecutionResult {
	status := summary.Status
	if status == "" {
		status = "succeeded"
	}
	errorMessage := ""
	errorCode := ""
	exitCode := int32(0)
	if err != nil {
		status = "failed"
		errorMessage = err.Error()
		var exitErr exit.ExitCoder
		if errors.As(err, &exitErr) {
			exitCode = int32(exitErr.ExitCode())
		}
	}
	if code, ok := result.Metadata["error_code"]; ok {
		errorCode = code
	}
	outputs := make([]model.OutputRecord, 0, len(result.Outputs))
	for _, out := range result.Outputs {
		outputs = append(outputs, model.OutputRecord{
			Path:  out.Path,
			Label: out.Label,
		})
	}
	return model.ExecutionResult{
		Status: status,
		Summary: model.ExecutionSummary{
			Command:         summary.Command,
			Status:          status,
			DurationSeconds: summary.Duration.Seconds(),
			Risks:           summary.Risks,
			Notes:           summary.Notes,
			Outputs:         outputs,
			ErrorMessage:    errorMessage,
		},
		Artifacts:  outputs,
		Error:      errorMessage,
		Metadata:   cloneStringMap(result.Metadata),
		ExitCode:   exitCode,
		ErrorCode:  errorCode,
		ReportedAt: time.Now().UTC(),
	}
}

func cloneStringMap(src map[string]string) map[string]string {
	if len(src) == 0 {
		return nil
	}
	dst := make(map[string]string, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}
