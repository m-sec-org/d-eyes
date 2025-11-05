package main

import (
	"context"
	"flag"
	"log"

	"github.com/m-sec-org/d-eyes/server/internal/app"
	"github.com/m-sec-org/d-eyes/server/internal/config"
)

func main() {
	configPath := flag.String("config", "", "Path to server configuration file")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := app.Run(ctx, cfg); err != nil {
		log.Fatalf("server exited with error: %v", err)
	}
}
