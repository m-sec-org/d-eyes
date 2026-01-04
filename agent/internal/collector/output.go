package collector

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/m-sec-org/d-eyes/agent/internal/debugger"
)

func buildOutputHandler(cfg Config, base EventHandler, emitter *debugger.Emitter) (EventHandler, func(), error) {
	mode := strings.TrimSpace(strings.ToLower(cfg.Output.Mode))
	streamCfg := cfg.Output.Stream
	streamEnabled := mode == "stream" || strings.TrimSpace(streamCfg.URL) != ""
	if mode == "" && !streamEnabled {
		if base == nil {
			return EventHandlerFunc(func(context.Context, *SystemEvent) error { return nil }), nil, nil
		}
		return base, nil, nil
	}
	var writer EventHandler
	var cleanup func()
	var err error
	switch {
	case streamEnabled:
		writer, cleanup, err = newStreamWriter(streamCfg, emitter)
	case mode == "stdout":
		writer = newStdoutWriter()
	case mode == "file":
		writer, cleanup, err = newFileWriter(cfg.Output.Path)
	default:
		// no-op
	}
	if err != nil {
		return nil, nil, err
	}
	var chain []EventHandler
	if writer != nil {
		chain = append(chain, writer)
	}
	if base != nil {
		chain = append(chain, base)
	}
	if len(chain) == 0 {
		return EventHandlerFunc(func(context.Context, *SystemEvent) error { return nil }), cleanup, nil
	}
	if len(chain) == 1 {
		return chain[0], cleanup, nil
	}
	return EventHandlerFunc(func(ctx context.Context, event *SystemEvent) error {
		for _, h := range chain {
			if err := h.HandleEvent(ctx, event); err != nil {
				return err
			}
		}
		return nil
	}), cleanup, nil
}

func newStdoutWriter() EventHandler {
	var mu sync.Mutex
	encoder := json.NewEncoder(os.Stdout)
	return EventHandlerFunc(func(_ context.Context, event *SystemEvent) error {
		if event == nil {
			return nil
		}
		mu.Lock()
		defer mu.Unlock()
		return encoder.Encode(event)
	})
}

func newFileWriter(path string) (EventHandler, func(), error) {
	if strings.TrimSpace(path) == "" {
		path = filepath.Join(os.TempDir(), "d-eyes-events.jsonl")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, nil, fmt.Errorf("create output dir: %w", err)
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, nil, fmt.Errorf("open output file: %w", err)
	}
	var mu sync.Mutex
	encoder := json.NewEncoder(file)
	handler := EventHandlerFunc(func(_ context.Context, event *SystemEvent) error {
		if event == nil {
			return nil
		}
		mu.Lock()
		defer mu.Unlock()
		return encoder.Encode(event)
	})
	cleanup := func() {
		_ = file.Close()
	}
	return handler, cleanup, nil
}
