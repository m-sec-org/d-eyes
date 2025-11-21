package main

import (
	"log"
	"os"

	"github.com/m-sec-org/d-eyes/agent/internal/agent"
)

type runtimeRunner interface {
	Run(args []string) (int, error)
}

var (
	runtimeFactory = func() runtimeRunner { return agent.NewRuntime() }
	exitFunc       = os.Exit
)

func runAgentCLI(args []string) int {
	rt := runtimeFactory()
	code, err := rt.Run(args)
	if err != nil {
		log.Printf("agent terminated with error: %v\n", err)
	}
	return code
}

func main() {
	exitFunc(runAgentCLI(os.Args))
}
