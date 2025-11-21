package main

import (
	"errors"
	"os"
	"testing"

	"github.com/m-sec-org/d-eyes/agent/internal/agent"
)

type fakeRuntime struct {
	code int
	err  error
	args []string
}

func (f *fakeRuntime) Run(args []string) (int, error) {
	f.args = args
	return f.code, f.err
}

func TestRunAgentCLIReturnsExitCode(t *testing.T) {
	runtime := &fakeRuntime{code: 5, err: errors.New("boom")}
	runtimeFactory = func() runtimeRunner { return runtime }
	exitFunc = func(int) {}
	defer func() {
		runtimeFactory = func() runtimeRunner { return agent.NewRuntime() }
		exitFunc = os.Exit
	}()

	code := runAgentCLI([]string{"d-eyes", "version"})
	if code != 5 {
		t.Fatalf("runAgentCLI should return 5")
	}
}

func TestMainUsesExitFunc(t *testing.T) {
	runtimeFactory = func() runtimeRunner { return &fakeRuntime{code: 0} }
	called := 0
	exitFunc = func(code int) { called = code }
	defer func() {
		runtimeFactory = func() runtimeRunner { return agent.NewRuntime() }
		exitFunc = os.Exit
	}()
	main()
	if called != 0 {
		t.Fatalf("main should pass exit code to exitFunc")
	}
}
