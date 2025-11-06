package tasks

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/m-sec-org/d-eyes/agent/internal/benchmark"
	"github.com/m-sec-org/d-eyes/agent/internal/benchmarkexec"
	"github.com/m-sec-org/d-eyes/agent/pkg/reporting"
)

type baselineRunner struct{}

func BaselineRunner() TaskRunner {
	return &baselineRunner{}
}

func (b *baselineRunner) Run(ctx context.Context, req TaskRequest) (TaskResult, error) {
	if req.Manager == nil {
		return TaskResult{}, errors.New("report manager missing")
	}
	scope := getStringFlag(req.Flags, "scope", "all")
	profile := req.Profile
	if profile == "default" || profile == "" {
		profile = scope
	}
	reqName := fmt.Sprintf("%s-%s", req.Name, profile)

	format := strings.ToLower(req.Format)
	if format == "" {
		format = "json"
	}
	ext := format
	switch format {
	case "json":
		ext = "json"
	case "csv":
		ext = "csv"
	case "html":
		ext = "html"
	default:
		ext = "json"
		format = "json"
	}

	file, path, err := req.Manager.CreateFile("baseline", reqName, ext)
	if err != nil {
		return TaskResult{}, err
	}
	file.Close()

	benchReq := benchmarkexec.Request{
		Scope:      scope,
		ConfigPath: getStringFlag(req.Flags, "baseline-config", ""),
		Timeout:    req.Timeout,
		Verbose:    getBoolFlag(req.Flags, "verbose"),
		Debug:      getBoolFlag(req.Flags, "debug"),
	}
	if benchReq.Timeout <= 0 {
		benchReq.Timeout = req.Config.Performance.Timeout
	}
	result, err := benchmarkexec.Execute(ctx, benchReq)
	if err != nil {
		return TaskResult{}, err
	}

	output := struct {
		Scope     string                  `json:"scope"`
		Duration  string                  `json:"duration"`
		Summary   map[string]int          `json:"summary"`
		Checks    []benchmark.CheckResult `json:"checks"`
		Warnings  []string                `json:"warnings"`
		Generated time.Time               `json:"generated"`
	}{
		Scope:     scope,
		Duration:  result.Duration.String(),
		Summary:   result.SeverityCount,
		Checks:    result.Checks,
		Warnings:  result.Warnings,
		Generated: time.Now().UTC(),
	}

	if err := writeBaselineReport(path, format, output); err != nil {
		return TaskResult{}, err
	}

	metadata := map[string]string{
		"scope":          scope,
		"profile":        profile,
		"format":         format,
		"report_path":    path,
		"checks_total":   fmt.Sprintf("%d", len(result.Checks)),
		"baseline_scope": scope,
	}
	if benchReq.ConfigPath != "" {
		metadata["baseline_config"] = benchReq.ConfigPath
	}

	return TaskResult{
		Outputs:  []reporting.OutputRecord{{Label: "基线检查", Path: path}},
		Risks:    result.SeverityCount,
		Notes:    result.Warnings,
		Metadata: metadata,
	}, nil
}

func getStringFlag(flags map[string]any, name, fallback string) string {
	if flags == nil {
		return fallback
	}
	if val, ok := flags[name]; ok {
		if s, ok := val.(string); ok && strings.TrimSpace(s) != "" {
			return s
		}
	}
	return fallback
}

func getBoolFlag(flags map[string]any, name string) bool {
	if flags == nil {
		return false
	}
	if val, ok := flags[name]; ok {
		switch v := val.(type) {
		case bool:
			return v
		case string:
			return strings.ToLower(strings.TrimSpace(v)) == "true"
		}
	}
	return false
}

func writeBaselineReport(path, format string, payload any) error {
	switch format {
	case "json":
		file, err := os.Create(path)
		if err != nil {
			return err
		}
		encoder := json.NewEncoder(file)
		encoder.SetIndent("", "  ")
		err = encoder.Encode(payload)
		file.Close()
		return err
	default:
		file, err := os.Create(path)
		if err != nil {
			return err
		}
		m := payload.(struct {
			Scope     string                  `json:"scope"`
			Duration  string                  `json:"duration"`
			Summary   map[string]int          `json:"summary"`
			Checks    []benchmark.CheckResult `json:"checks"`
			Warnings  []string                `json:"warnings"`
			Generated time.Time               `json:"generated"`
		})
		builder := strings.Builder{}
		builder.WriteString(fmt.Sprintf("Scope: %s\n", m.Scope))
		builder.WriteString(fmt.Sprintf("Duration: %s\n", m.Duration))
		builder.WriteString("Summary:\n")
		for level, count := range m.Summary {
			builder.WriteString(fmt.Sprintf("  - %s: %d\n", level, count))
		}
		builder.WriteString("Warnings:\n")
		if len(m.Warnings) == 0 {
			builder.WriteString("  (none)\n")
		} else {
			for _, w := range m.Warnings {
				builder.WriteString("  - ")
				builder.WriteString(w)
				builder.WriteString("\n")
			}
		}
		builder.WriteString("Checks:\n")
		for _, check := range m.Checks {
			builder.WriteString(fmt.Sprintf("  - [%s] %s: %s\n", check.Severity, check.ID, check.Status))
		}
		_, err = file.WriteString(builder.String())
		file.Close()
		return err
	}
}
