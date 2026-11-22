package main

import (
	"context"
	"log/slog"
	"testing"
)

func TestSetupSlogLevels(t *testing.T) {
	old := slog.Default()
	t.Cleanup(func() { slog.SetDefault(old) })

	setupSlog(false)
	if slog.Default().Enabled(context.Background(), slog.LevelDebug) {
		t.Error("debug enabled without -d")
	}
	if !slog.Default().Enabled(context.Background(), slog.LevelInfo) {
		t.Error("info disabled")
	}
	setupSlog(true)
	if !slog.Default().Enabled(context.Background(), slog.LevelDebug) {
		t.Error("debug not enabled with -d")
	}
}
