package main

import (
	"log"
	"os"

	"github.com/m-sec-org/d-eyes/agent/internal/agent"
)

func main() {
	rt := agent.NewRuntime()
	code, err := rt.Run(os.Args)
	if err != nil {
		log.Printf("agent terminated with error: %v\n", err)
	}
	os.Exit(code)
}
