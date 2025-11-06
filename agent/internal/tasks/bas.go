package tasks

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/m-sec-org/d-eyes/agent/internal/sandbox"
	"github.com/m-sec-org/d-eyes/agent/pkg/reporting"
)

//go:embed bas_scenarios/*.json
var embeddedBAScenarios embed.FS

type basRunner struct{}

// BASRunner returns a TaskRunner for BAS scenarios.
func BASRunner() TaskRunner {
	return &basRunner{}
}

type Scenario struct {
	ID          string         `json:"id"`
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	Tags        []string       `json:"tags,omitempty"`
	Variables   map[string]any `json:"variables,omitempty"`
	Steps       []ScenarioStep `json:"steps"`
}

type ScenarioStep struct {
	ID             string            `json:"id"`
	Name           string            `json:"name"`
	Description    string            `json:"description,omitempty"`
	Command        string            `json:"command,omitempty"`
	Args           []string          `json:"args,omitempty"`
	Env            map[string]string `json:"env,omitempty"`
	WorkingDir     string            `json:"working_dir,omitempty"`
	TimeoutSeconds int               `json:"timeout_seconds,omitempty"`
	UseSandbox     bool              `json:"use_sandbox"`
	Severity       string            `json:"severity,omitempty"`
}

type stepOutcome struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Status    string    `json:"status"`
	ExitCode  int       `json:"exit_code"`
	StartedAt time.Time `json:"started_at"`
	EndedAt   time.Time `json:"ended_at"`
	Stdout    string    `json:"stdout,omitempty"`
	Stderr    string    `json:"stderr,omitempty"`
	Message   string    `json:"message,omitempty"`
	Sandbox   bool      `json:"sandbox"`
	Sandboxed bool      `json:"sandboxed"`
	Fallback  bool      `json:"fallback"`
}

type scenarioReport struct {
	ScenarioID   string        `json:"scenario_id"`
	ScenarioName string        `json:"scenario_name"`
	Description  string        `json:"description,omitempty"`
	ExecutedAt   time.Time     `json:"executed_at"`
	Steps        []stepOutcome `json:"steps"`
	Summary      struct {
		Total   int `json:"total"`
		Success int `json:"success"`
		Failed  int `json:"failed"`
		Skipped int `json:"skipped"`
	} `json:"summary"`
	Notes []string `json:"notes,omitempty"`
}

func (b *basRunner) Run(ctx context.Context, req TaskRequest) (TaskResult, error) {
	scenario, err := loadScenario(req)
	if err != nil {
		return TaskResult{}, err
	}
	if len(scenario.Steps) == 0 {
		return TaskResult{}, errors.New("bas scenario has no steps")
	}

	manager := sandbox.NewManager(sandbox.Config{
		Enabled:        req.Config.Sandbox.Enabled,
		Runtime:        req.Config.Sandbox.Runtime,
		RuntimeBinary:  req.Config.Sandbox.RuntimeBinary,
		SharedPaths:    append([]string(nil), req.Config.Sandbox.SharedPaths...),
		TempDir:        req.Config.Sandbox.TempDir,
		Allowed:        append([]string(nil), req.Config.Sandbox.AllowedCommands...),
		Denied:         append([]string(nil), req.Config.Sandbox.DeniedCommands...),
		LogPath:        req.Config.Sandbox.LogPath,
		FallbackToHost: req.Config.Sandbox.FallbackToHost,
	})
	outcomes := make([]stepOutcome, 0, len(scenario.Steps))
	riskTotals := make(map[string]int)
	notes := make([]string, 0)
	failedSteps := make([]string, 0)
	sandboxUsed := false
	sandboxFallback := false

	failureEncountered := false

	for _, step := range scenario.Steps {
		select {
		case <-ctx.Done():
			return TaskResult{
				Outputs: nil,
				Risks:   riskTotals,
				Notes:   append(notes, "任务被取消"),
				Metadata: map[string]string{
					"scenario_id":          scenario.ID,
					"scenario_name":        scenario.Name,
					"scenario_description": scenario.Description,
					"scenario_tags":        strings.Join(scenario.Tags, ","),
				},
			}, ctx.Err()
		default:
		}

		if failureEncountered {
			outcome := skippedOutcome(step, req.Config.Sandbox.Enabled, "skipped due to previous failure")
			outcomes = append(outcomes, outcome)
			riskTotals["low"]++
			if outcome.Message != "" {
				notes = append(notes, fmt.Sprintf("%s: %s", outcome.Name, outcome.Message))
			}
			continue
		}

		outcome := executeScenarioStep(ctx, scenario, step, manager, req.Config.Sandbox.Enabled, req.SandboxApproved)
		outcomes = append(outcomes, outcome)
		if outcome.Sandboxed {
			sandboxUsed = true
		}
		if outcome.Fallback {
			sandboxFallback = true
		}
		switch outcome.Status {
		case "succeeded":
			riskTotals["info"]++
		case "failed":
			failureEncountered = true
			failedSteps = append(failedSteps, outcome.ID)
			severity := strings.ToLower(strings.TrimSpace(step.Severity))
			if severity == "" {
				severity = "high"
			}
			riskTotals[severity]++
		case "skipped":
			riskTotals["low"]++
		}
		if outcome.Message != "" {
			notes = append(notes, fmt.Sprintf("%s: %s", outcome.Name, outcome.Message))
		}
		if outcome.Fallback {
			notes = append(notes, fmt.Sprintf("%s: 沙箱运行时不可用，已回退至宿主执行", outcome.Name))
		}
	}

	if failureEncountered {
		notes = append(notes, "场景执行过程中出现失败，后续步骤已跳过")
	}

	report := scenarioReport{
		ScenarioID:   scenario.ID,
		ScenarioName: scenario.Name,
		Description:  scenario.Description,
		ExecutedAt:   time.Now().UTC(),
		Steps:        outcomes,
	}
	for _, step := range outcomes {
		switch step.Status {
		case "succeeded":
			report.Summary.Success++
		case "failed":
			report.Summary.Failed++
		case "skipped":
			report.Summary.Skipped++
		}
	}
	report.Summary.Total = len(outcomes)
	report.Notes = notes

	summaryPath, err := writeScenarioReport(req, scenario, report)
	if err != nil {
		return TaskResult{}, err
	}

	metadata := map[string]string{
		"scenario_id":          scenario.ID,
		"scenario_name":        scenario.Name,
		"scenario_description": scenario.Description,
		"scenario_tags":        strings.Join(scenario.Tags, ","),
		"scenario_steps":       strconv.Itoa(len(scenario.Steps)),
		"steps_success":        strconv.Itoa(report.Summary.Success),
		"steps_failed":         strconv.Itoa(report.Summary.Failed),
		"steps_skipped":        strconv.Itoa(report.Summary.Skipped),
		"sandbox_enabled":      strconv.FormatBool(req.Config.Sandbox.Enabled),
		"sandbox_runtime":      req.Config.Sandbox.Runtime,
		"sandbox_runtime_bin":  req.Config.Sandbox.RuntimeBinary,
		"scenario_summary":     serializeScenarioSteps(outcomes),
	}
	if sandboxUsed {
		metadata["sandbox_executed"] = "true"
	}
	if sandboxFallback {
		metadata["sandbox_fallback"] = "true"
	}
	if req.Config.Sandbox.RequireApproval {
		metadata["sandbox_approval_required"] = "true"
		if req.SandboxApproved {
			metadata["sandbox_approved"] = "true"
		}
	}
	if len(failedSteps) > 0 {
		metadata["failed_steps"] = strings.Join(failedSteps, ",")
		metadata["error_code"] = "bas.step_failed"
	}

	outputs := []reporting.OutputRecord{
		{Label: "BAS 场景报告", Path: summaryPath},
	}

	var execErr error
	if len(failedSteps) > 0 {
		execErr = fmt.Errorf("BAS 场景 %s 执行失败，失败步骤: %s", scenario.ID, strings.Join(failedSteps, ","))
	}

	result := TaskResult{
		Outputs:  outputs,
		Risks:    riskTotals,
		Notes:    notes,
		Metadata: metadata,
	}
	return result, execErr
}

func loadScenario(req TaskRequest) (Scenario, error) {
	if req.Flags == nil {
		return Scenario{}, errors.New("bas scenario payload missing")
	}

	if id := strings.TrimSpace(getStringFlag(req.Flags, "scenario-id", "")); id != "" {
		scenario, err := loadScenarioByID(req, id)
		if err != nil {
			return Scenario{}, err
		}
		return normaliseScenario(scenario, id), nil
	}

	if filePath := strings.TrimSpace(getStringFlag(req.Flags, "scenario-file", "")); filePath != "" {
		data, err := os.ReadFile(filepath.Clean(filePath))
		if err != nil {
			return Scenario{}, fmt.Errorf("read scenario file: %w", err)
		}
		req.Flags["scenario"] = string(data)
	}

	raw := req.Flags["scenario"]
	switch value := raw.(type) {
	case string:
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			return Scenario{}, errors.New("scenario string is empty")
		}
		if looksLikeJSON(trimmed) {
			scenario, err := parseScenarioFromString(trimmed)
			if err != nil {
				return Scenario{}, err
			}
			return normaliseScenario(scenario, scenarioIDFromRequest(req, scenario)), nil
		}
		scenario, err := loadScenarioByID(req, trimmed)
		if err != nil {
			return Scenario{}, err
		}
		return normaliseScenario(scenario, trimmed), nil
	case []byte:
		scenario, err := parseScenarioFromString(string(value))
		if err != nil {
			return Scenario{}, err
		}
		return normaliseScenario(scenario, scenarioIDFromRequest(req, scenario)), nil
	case map[string]any:
		scenario, err := parseScenarioFromMap(value)
		if err != nil {
			return Scenario{}, err
		}
		return normaliseScenario(scenario, scenarioIDFromRequest(req, scenario)), nil
	default:
		return Scenario{}, errors.New("invalid scenario definition")
	}
}

func loadScenarioByID(req TaskRequest, id string) (Scenario, error) {
	sanitisedID := sanitiseScenarioID(id)
	if dir := strings.TrimSpace(req.Config.Tasks.BAS.ScenarioDir); dir != "" {
		if scenario, err := loadScenarioFromDir(dir, sanitisedID); err == nil {
			return scenario, nil
		} else if !errors.Is(err, fs.ErrNotExist) {
			return Scenario{}, err
		}
	}
	return loadEmbeddedScenario(sanitisedID)
}

func parseScenarioFromString(data string) (Scenario, error) {
	var scenario Scenario
	if err := json.Unmarshal([]byte(data), &scenario); err != nil {
		return Scenario{}, fmt.Errorf("decode scenario json: %w", err)
	}
	return scenario, nil
}

func parseScenarioFromMap(m map[string]any) (Scenario, error) {
	bytes, err := json.Marshal(m)
	if err != nil {
		return Scenario{}, err
	}
	return parseScenarioFromString(string(bytes))
}

func writeScenarioReport(req TaskRequest, scenario Scenario, report scenarioReport) (string, error) {
	file, path, err := req.Manager.CreateFile("bas", scenarioFileName(scenario), "json")
	if err != nil {
		return "", err
	}
	defer file.Close()
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(report); err != nil {
		return "", err
	}
	return path, nil
}

func scenarioFileName(scenario Scenario) string {
	if scenario.ID != "" {
		return sanitiseScenarioID(scenario.ID)
	}
	if scenario.Name != "" {
		return sanitiseScenarioID(scenario.Name)
	}
	return "bas-scenario"
}

func executeScenarioStep(ctx context.Context, scenario Scenario, step ScenarioStep, manager *sandbox.Manager, sandboxEnabled bool, approved bool) stepOutcome {
	start := time.Now()
	outcome := stepOutcome{
		ID:        step.ID,
		Name:      step.Name,
		Status:    "skipped",
		StartedAt: start,
		EndedAt:   start,
		Message:   "",
		Sandbox:   sandboxEnabled && step.UseSandbox,
	}

	cmd := strings.TrimSpace(step.Command)
	if cmd == "" {
		outcome.Message = "command empty, skipped"
		outcome.EndedAt = time.Now()
		return outcome
	}

	timeout := time.Duration(step.TimeoutSeconds) * time.Second
	runRequest := sandbox.RunRequest{
		Command:    cmd,
		Args:       append([]string(nil), step.Args...),
		Env:        cloneEnv(step.Env),
		WorkingDir: step.WorkingDir,
		Timeout: func() time.Duration {
			if timeout > 0 {
				return timeout
			}
			return 5 * time.Minute
		}(),
		UseSandbox:      outcome.Sandbox,
		SandboxApproved: approved,
		Identifier:      fmt.Sprintf("%s:%s:%s", strings.TrimSpace(scenario.ID), strings.TrimSpace(step.ID), step.Name),
	}
	runResult, err := manager.Run(ctx, runRequest)
	outcome.EndedAt = runResult.FinishedAt
	outcome.Stdout = runResult.Stdout
	outcome.Stderr = runResult.Stderr
	outcome.ExitCode = runResult.ExitCode
	outcome.Sandboxed = runResult.Sandboxed
	outcome.Fallback = runResult.Fallback

	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			outcome.Status = "failed"
			outcome.Message = "step timeout"
			return outcome
		}
		outcome.Status = "failed"
		outcome.Message = err.Error()
		return outcome
	}

	if runResult.ExitCode != 0 {
		outcome.Status = "failed"
		outcome.Message = fmt.Sprintf("exit code %d", runResult.ExitCode)
		return outcome
	}

	outcome.Status = "succeeded"
	outcome.Message = "completed"
	return outcome
}

func skippedOutcome(step ScenarioStep, sandboxEnabled bool, reason string) stepOutcome {
	now := time.Now()
	if strings.TrimSpace(reason) == "" {
		reason = "skipped"
	}
	return stepOutcome{
		ID:        step.ID,
		Name:      step.Name,
		Status:    "skipped",
		StartedAt: now,
		EndedAt:   now,
		Message:   reason,
		Sandbox:   sandboxEnabled && step.UseSandbox,
	}
}

func serializeScenarioSteps(steps []stepOutcome) string {
	data, err := json.Marshal(steps)
	if err != nil {
		return "[]"
	}
	return string(data)
}

func loadScenarioFromDir(dir, id string) (Scenario, error) {
	candidates := []string{
		filepath.Join(dir, id+".json"),
		filepath.Join(dir, id+".yaml"),
		filepath.Join(dir, id+".yml"),
	}
	for _, candidate := range candidates {
		data, err := os.ReadFile(filepath.Clean(candidate))
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return Scenario{}, fmt.Errorf("read scenario %s: %w", id, err)
		}
		return parseScenarioFromString(string(data))
	}
	return Scenario{}, fs.ErrNotExist
}

func loadEmbeddedScenario(id string) (Scenario, error) {
	data, err := embeddedBAScenarios.ReadFile(fmt.Sprintf("bas_scenarios/%s.json", id))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return Scenario{}, fmt.Errorf("scenario %s not found", id)
		}
		return Scenario{}, fmt.Errorf("load embedded scenario %s: %w", id, err)
	}
	return parseScenarioFromString(string(data))
}

func normaliseScenario(s Scenario, fallback string) Scenario {
	sanitised := sanitiseScenarioID(fallback)
	if s.ID == "" {
		s.ID = sanitised
	}
	if s.Name == "" {
		s.Name = s.ID
	}
	for i := range s.Steps {
		if s.Steps[i].ID == "" {
			s.Steps[i].ID = fmt.Sprintf("step-%02d", i+1)
		}
		if s.Steps[i].Name == "" {
			s.Steps[i].Name = s.Steps[i].ID
		}
	}
	return s
}

func looksLikeJSON(data string) bool {
	for _, r := range data {
		if unicode.IsSpace(r) {
			continue
		}
		return r == '{' || r == '['
	}
	return false
}

func sanitiseScenarioID(id string) string {
	id = strings.TrimSpace(id)
	if id == "" {
		return "scenario"
	}
	id = strings.ToLower(id)
	id = strings.ReplaceAll(id, "_", "-")
	id = strings.ReplaceAll(id, " ", "-")
	id = strings.ReplaceAll(id, "/", "-")
	id = strings.Trim(id, "-.")
	if id == "" {
		return "scenario"
	}
	return id
}

func scenarioIDFromRequest(req TaskRequest, scenario Scenario) string {
	if scenario.ID != "" {
		return scenario.ID
	}
	if scenario.Name != "" {
		return scenario.Name
	}
	if req.Flags != nil {
		if id := getStringFlag(req.Flags, "scenario-id", ""); id != "" {
			return id
		}
		if raw := req.Flags["scenario"]; raw != nil {
			if text, ok := raw.(string); ok && strings.TrimSpace(text) != "" {
				return text
			}
		}
	}
	if req.Name != "" {
		return req.Name
	}
	return "scenario"
}

func cloneEnv(src map[string]string) map[string]string {
	if len(src) == 0 {
		return nil
	}
	dst := make(map[string]string, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}
