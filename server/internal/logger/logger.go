package logger

import (
	"log/slog"
	"os"
)

// New constructs a slog.Logger with JSON handler by default.
func New() *slog.Logger {
	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})
	return slog.New(handler)
}
