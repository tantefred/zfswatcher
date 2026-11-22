package notifier

import (
	"bytes"
	"errors"
	"log/slog"
	"strings"
	"testing"
)

func TestInternalErrorUsesSlog(t *testing.T) {
	var buf bytes.Buffer
	old := slog.Default()
	t.Cleanup(func() { slog.SetDefault(old) })
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))

	checkInternalError("no error", nil)
	if buf.Len() != 0 {
		t.Fatalf("unexpected output: %q", buf.String())
	}
	checkInternalError("something failed", errors.New("boom"))
	internalError("plain")
	out := buf.String()
	for _, want := range []string{"level=ERROR", "something failed", "boom", "component=notifier", "plain"} {
		if !strings.Contains(out, want) {
			t.Errorf("output %q lacks %q", out, want)
		}
	}
}
