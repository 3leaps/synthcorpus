//go:build unix

package guardrail

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestPrepareOutputRootRejectsFIFOMarker(t *testing.T) {
	out := filepath.Join(t.TempDir(), "dogfood")
	if err := os.MkdirAll(out, DirPerm); err != nil {
		t.Fatal(err)
	}
	markerPath := filepath.Join(out, MarkerName)
	if err := syscall.Mkfifo(markerPath, 0o600); err != nil {
		t.Fatalf("create FIFO marker fixture: %v", err)
	}

	// Rejection must happen via Lstat/mode before open — otherwise ReadFile
	// on a FIFO with no writer hangs indefinitely.
	done := make(chan error, 1)
	go func() {
		_, err := PrepareOutputRoot(out, true)
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "regular file") {
			t.Fatalf("expected FIFO marker rejection, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("FIFO marker check hung — opened special file before mode rejection")
	}
}
