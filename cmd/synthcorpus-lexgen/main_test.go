package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/3leaps/synthcorpus"
)

func TestVersionMatchesEmbeddedVersion(t *testing.T) {
	var stdout, stderr bytes.Buffer

	if err := run([]string{"--version"}, &stdout, &stderr); err != nil {
		t.Fatalf("--version: %v (%s)", err, stderr.String())
	}
	if got := strings.TrimSpace(stdout.String()); got != synthcorpus.Version() {
		t.Fatalf("--version printed %q, embedded version is %q", got, synthcorpus.Version())
	}
}

func TestRejectsUnknownProfile(t *testing.T) {
	var stdout, stderr bytes.Buffer

	err := run([]string{"--profile", "everything", "--out", t.TempDir()}, &stdout, &stderr)
	if err == nil {
		t.Fatal("an unknown profile was accepted")
	}
	if !strings.Contains(err.Error(), "profile") {
		t.Fatalf("error does not name the offending flag: %v", err)
	}
}

func TestRejectsPositionalArguments(t *testing.T) {
	var stdout, stderr bytes.Buffer

	if err := run([]string{"decernor"}, &stdout, &stderr); err == nil {
		t.Fatal("a stray positional argument was accepted")
	}
}

func TestRejectsSeedAboveContractRange(t *testing.T) {
	var stdout, stderr bytes.Buffer

	err := run([]string{"--seed", "4294967296", "--out", t.TempDir()}, &stdout, &stderr)
	if err == nil {
		t.Fatal("a seed outside the 32-bit contract range was accepted")
	}
	if !strings.Contains(err.Error(), "seed") {
		t.Fatalf("error does not name the offending flag: %v", err)
	}
}

func TestGeneratesAndReportsDigests(t *testing.T) {
	var stdout, stderr bytes.Buffer
	root := filepath.Join(t.TempDir(), "corpus")

	if err := run([]string{"--seed", "7312026", "--out", root}, &stdout, &stderr); err != nil {
		t.Fatalf("generate: %v (%s)", err, stderr.String())
	}

	out := stdout.String()
	for _, want := range []string{"fixtures sha256:", "manifest sha256:", "cases:"} {
		if !strings.Contains(out, want) {
			t.Fatalf("output is missing %q:\n%s", want, out)
		}
	}
	if _, err := os.Stat(filepath.Join(root, "fixtures.json")); err != nil {
		t.Fatalf("fixture set was not written: %v", err)
	}
}

// TestRefusesRepeatRunWithoutForce keeps the destructive path behind an
// explicit flag.
func TestRefusesRepeatRunWithoutForce(t *testing.T) {
	var stdout, stderr bytes.Buffer
	root := filepath.Join(t.TempDir(), "corpus")

	if err := run([]string{"--seed", "1", "--out", root}, &stdout, &stderr); err != nil {
		t.Fatalf("first run: %v (%s)", err, stderr.String())
	}
	if err := run([]string{"--seed", "1", "--out", root}, &stdout, &stderr); err == nil {
		t.Fatal("a second run without --force replaced an existing corpus")
	}
}
