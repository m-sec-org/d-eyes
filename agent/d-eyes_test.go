package main

import (
	"os"
	"testing"

	"github.com/m-sec-org/d-eyes/agent/internal/agent"
)

type fakeRuntime2 struct{ code int }

func (f *fakeRuntime2) Run(args []string) (int, error) { return f.code, nil }

func TestRootMainUsesExit(t *testing.T) {
	rootRuntimeFactory = func() runtimeRunner { return &fakeRuntime2{code: 7} }
	called := -1
	rootExitFunc = func(code int) { called = code }
	defer func() {
		rootRuntimeFactory = func() runtimeRunner { return agent.NewRuntime() }
		rootExitFunc = os.Exit
	}()
	main()
	if called != 7 {
		t.Fatalf("expected exit code 7, got %d", called)
	}
}
