package main

import (
	"os"

	"github.com/m-sec-org/d-eyes/agent/internal/agent"
)

func main() {
	rt := agent.NewRuntime()
	code, _ := rt.Run(os.Args)
	os.Exit(code)
}
