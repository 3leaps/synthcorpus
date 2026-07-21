package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVersionFlagMatchesVersionFile(t *testing.T) {
	wantBytes, err := os.ReadFile(filepath.Join("..", "..", "VERSION"))
	if err != nil {
		t.Fatal(err)
	}
	want := strings.TrimSpace(string(wantBytes))

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if err := run([]string{"-version"}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(stdout.String()); got != want {
		t.Fatalf("-version = %q, VERSION = %q", got, want)
	}
	if stderr.Len() != 0 {
		t.Fatalf("-version wrote stderr: %q", stderr.String())
	}
}
