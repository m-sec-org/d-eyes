package main

import (
	"os"

	"github.com/m-sec-org/d-eyes/agent/internal/agent"
)

type runtimeRunner interface {
	Run(args []string) (int, error)
}

var (
	rootRuntimeFactory = func() runtimeRunner { return agent.NewRuntime() }
	rootExitFunc       = os.Exit
)

func main() {
	rt := rootRuntimeFactory()
	code, _ := rt.Run(os.Args)
	rootExitFunc(code)
}
