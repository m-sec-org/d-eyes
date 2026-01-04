package engine

import (
	"context"
	"fmt"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/m-sec-org/d-eyes/agent/internal/cmdexec"
)

// Status represents the evaluation outcome of a rule or check.
type Status string

const (
	StatusPass  Status = "PASS"
	StatusFail  Status = "FAIL"
	StatusWarn  Status = "WARN"
	StatusError Status = "ERROR"
)

// Rule describes a baseline rule loaded from rule packs.
type Rule struct {
	ID          string      `yaml:"id"`
	Title       string      `yaml:"title"`
	Description string      `yaml:"description"`
	Severity    string      `yaml:"severity"`
	Platforms   []string    `yaml:"platforms"`
	Tags        []string    `yaml:"tags"`
	Remediation string      `yaml:"remediation"`
	References  []string    `yaml:"references"`
	Checks      []CheckSpec `yaml:"checks"`
}

// CheckSpec defines a single verification step of a rule.
type CheckSpec struct {
	Name        string     `yaml:"name"`
	Type        string     `yaml:"type"` // command, file etc (command by default)
	Command     string     `yaml:"command"`
	Args        []string   `yaml:"args"`
	Shell       bool       `yaml:"shell"`
	Timeout     int        `yaml:"timeout"`
	Optional    bool       `yaml:"optional"`
	FailOnError *bool      `yaml:"fail_on_error"`
	Expect      ExpectSpec `yaml:"expect"`
}

// ExpectSpec defines the expectation of a command or check result.
type ExpectSpec struct {
	Operator string `yaml:"operator"` // equals, contains, notContains, regex, exitCodeEquals
	Value    string `yaml:"value"`
	// ExitCode is used when operator is exitCodeEquals.
	ExitCode *int `yaml:"exit_code"`
}

// CheckDetail contains the outcome of a single check.
type CheckDetail struct {
	Name     string
	Command  string
	Status   Status
	Actual   string
	Expected string
	Message  string
}

// RuleResult contains aggregated outcome for a rule.
type RuleResult struct {
	Rule    Rule
	Status  Status
	Details []CheckDetail
}

// Executor abstracts command execution for testability.
type Executor interface {
	Run(ctx context.Context, command string, args []string, shell bool, timeout time.Duration) (stdout string, stderr string, exitCode int, err error)
}

// CommandExecutor executes commands using os/exec.
type CommandExecutor struct{}

// Run executes a command with timeout and returns combined output.
func (e *CommandExecutor) Run(ctx context.Context, command string, args []string, shell bool, timeout time.Duration) (string, string, int, error) {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	req := cmdexec.Request{
		Command: strings.TrimSpace(command),
		Args:    append([]string(nil), args...),
		Timeout: timeout,
	}
	if shell {
		req.Command, req.Args = shellCommand(command)
	}
	res, err := cmdexec.Run(ctx, req)
	return res.Stdout, res.Stderr, res.ExitCode, err
}

func shellCommand(command string) (string, []string) {
	command = strings.TrimSpace(command)
	if runtime.GOOS == "windows" {
		return "cmd", []string{"/c", command}
	}
	return "/bin/sh", []string{"-c", command}
}

// Runner evaluates rules using the provided executor.
type Runner struct {
	executor Executor
	now      func() time.Time
}

// Option configures Runner.
type Option func(*Runner)

// WithExecutor sets custom executor.
func WithExecutor(exec Executor) Option {
	return func(r *Runner) {
		r.executor = exec
	}
}

// WithNow overrides time provider.
func WithNow(f func() time.Time) Option {
	return func(r *Runner) {
		r.now = f
	}
}

// NewRunner creates a new Runner.
func NewRunner(opts ...Option) *Runner {
	r := &Runner{
		executor: &CommandExecutor{},
		now:      time.Now,
	}
	for _, opt := range opts {
		opt(r)
	}
	return r
}

// Run executes a rule and returns a detailed result.
func (r *Runner) Run(ctx context.Context, rule Rule) RuleResult {
	result := RuleResult{
		Rule:    rule,
		Status:  StatusPass,
		Details: make([]CheckDetail, 0, len(rule.Checks)),
	}

	for _, check := range rule.Checks {
		detail := r.executeCheck(ctx, rule, check)
		result.Details = append(result.Details, detail)

		switch detail.Status {
		case StatusFail:
			result.Status = StatusFail
		case StatusWarn:
			if result.Status != StatusFail {
				result.Status = StatusWarn
			}
		case StatusError:
			if result.Status == StatusPass {
				result.Status = StatusError
			}
		}
	}

	return result
}

func (r *Runner) executeCheck(ctx context.Context, rule Rule, check CheckSpec) CheckDetail {
	checkType := check.Type
	if checkType == "" {
		checkType = "command"
	}

	var detail CheckDetail
	detail.Name = check.Name
	if detail.Name == "" {
		detail.Name = checkType
	}

	switch checkType {
	case "command":
		return r.runCommandCheck(ctx, rule, check, detail)
	default:
		detail.Status = StatusWarn
		detail.Message = fmt.Sprintf("unsupported check type %s", checkType)
		return detail
	}
}

func (r *Runner) runCommandCheck(ctx context.Context, rule Rule, check CheckSpec, detail CheckDetail) CheckDetail {
	timeout := time.Duration(check.Timeout) * time.Second
	ctx = cmdexec.WithIdentifier(ctx, fmt.Sprintf("baseline rule=%s check=%s", rule.ID, check.Name))
	stdout, stderr, exitCode, err := r.executor.Run(ctx, check.Command, check.Args, check.Shell, timeout)
	detail.Command = strings.TrimSpace(strings.Join(append([]string{check.Command}, check.Args...), " "))
	detail.Actual = strings.TrimSpace(stdout)
	failOnError := true
	if check.FailOnError != nil {
		failOnError = *check.FailOnError
	}

	if err != nil && failOnError {
		detail.Status = StatusError
		detail.Message = strings.TrimSpace(stderr)
		if detail.Message == "" {
			detail.Message = err.Error()
		}
		return detail
	}

	expect := check.Expect
	detail.Expected = expect.Value
	pass := evaluateExpectation(expect, stdout, exitCode)
	if err != nil && !failOnError {
		// degrade to warn but still record actual output
		detail.Status = StatusWarn
		if stderr != "" {
			detail.Message = strings.TrimSpace(stderr)
		} else {
			detail.Message = err.Error()
		}
		return detail
	}

	if pass {
		detail.Status = StatusPass
		return detail
	}

	if check.Optional {
		detail.Status = StatusWarn
	} else {
		detail.Status = StatusFail
	}
	if stderr != "" {
		detail.Message = strings.TrimSpace(stderr)
	}
	return detail
}

func evaluateExpectation(expect ExpectSpec, stdout string, exitCode int) bool {
	operator := strings.ToLower(expect.Operator)
	value := expect.Value
	switch operator {
	case "equals":
		return strings.TrimSpace(stdout) == value
	case "contains":
		return strings.Contains(stdout, value)
	case "notcontains":
		return !strings.Contains(stdout, value)
	case "regex":
		ok, err := regexp.MatchString(value, stdout)
		return err == nil && ok
	case "exitcodeequals":
		if expect.ExitCode == nil {
			return false
		}
		return exitCode == *expect.ExitCode
	default:
		// unknown operator considered failure
		return false
	}
}
