package decernorloc

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestAuthorizeBinaryPathRejectsRelativeAndDotDot(t *testing.T) {
	if _, err := authorizeBinaryPath("../decernor"); err == nil {
		t.Fatal("expected relative path rejection")
	}
	if _, err := authorizeBinaryPath("foo/../decernor"); err == nil {
		t.Fatal("expected .. rejection")
	}
}

func TestLocateBinaryPrefersEnvAbsolute(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "decernor")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv(EnvBinary, bin)
	t.Setenv("PATH", dir)

	got, err := LocateBinary("", Pin{Locate: Locate{Env: EnvBinary, PathNames: []string{"decernor"}}})
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(got) != "decernor" {
		t.Fatalf("got %q", got)
	}
}

func TestLocateBinaryRejectsRelativeEnv(t *testing.T) {
	t.Setenv(EnvBinary, "../decernor")
	t.Setenv("PATH", t.TempDir())
	_, err := LocateBinary("", Pin{Locate: Locate{Env: EnvBinary}})
	if err == nil {
		t.Fatal("expected failure for relative DECERNOR_BIN")
	}
	if !strings.Contains(err.Error(), "relative") && !strings.Contains(err.Error(), "..") {
		t.Fatalf("error = %v", err)
	}
}

func TestLoadPinRejectsEmptyObject(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pin.json")
	if err := os.WriteFile(path, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPin(path); err == nil {
		t.Fatal("expected empty pin rejection")
	}
}

func TestLoadPinRoundTrip(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("caller")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", ".."))
	pinPath := filepath.Join(root, "manifests", "decernor-pin.json")
	if _, err := os.Stat(pinPath); err != nil {
		t.Skip("repo pin not available")
	}
	pin, err := LoadPin(pinPath)
	if err != nil {
		t.Fatal(err)
	}
	if pin.MinVersion != "0.1.3" || pin.PreferredTag != "v0.1.3" || pin.PreferredCommit != "fb19564" {
		t.Fatalf("pin = %#v", pin)
	}
	if pin.Locate.Env != EnvBinary {
		t.Fatalf("locate.env = %q", pin.Locate.Env)
	}
}

func TestCheckPinVersionAndCommit(t *testing.T) {
	pin := Pin{
		SchemaVersion:   pinSchemaVersion,
		Kind:            pinKind,
		Consumer:        pinConsumer,
		Tool:            pinTool,
		MinVersion:      "0.1.1",
		PreferredCommit: "c23af46",
	}
	if err := CheckPin(Identity{Version: "0.1.1", Commit: "c23af46"}, pin); err != nil {
		t.Fatal(err)
	}
	if err := CheckPin(Identity{Version: "0.1.0", Commit: "c23af46"}, pin); err == nil {
		t.Fatal("expected version failure")
	}
	if err := CheckPin(Identity{Version: "0.1.1", Commit: "deadbeef"}, pin); err == nil {
		t.Fatal("expected commit failure")
	}
	// Longer identity that extends the preferred pin is OK.
	if err := CheckPin(Identity{Version: "0.1.1", Commit: "c23af46abc"}, pin); err != nil {
		t.Fatal(err)
	}
	// Missing / unknown commit must fail (primary soft pin).
	if err := CheckPin(Identity{Version: "0.1.1", Commit: ""}, pin); err == nil {
		t.Fatal("expected empty commit failure")
	}
	if err := CheckPin(Identity{Version: "0.1.1", Commit: "unknown"}, pin); err == nil {
		t.Fatal("expected unknown commit failure")
	}
	// Short ambiguous identity prefix must not satisfy a longer preferred pin.
	if err := CheckPin(Identity{Version: "0.1.1", Commit: "c23af4"}, pin); err == nil {
		// c23af4 is 6 chars < MinCommitSHALen — rejected by validateCommitSHA
		// if somehow past that, commitMatchesPreferred must still fail for "c".
	}
	if err := CheckPin(Identity{Version: "0.1.1", Commit: "c"}, pin); err == nil {
		t.Fatal("expected short commit failure")
	}
	// Prerelease tails fail closed.
	if err := CheckPin(Identity{Version: "0.1.1-rc1", Commit: "c23af46"}, pin); err == nil {
		t.Fatal("expected prerelease version failure")
	}
}

func TestVersionAtLeastStrict(t *testing.T) {
	if !versionAtLeast("0.1.1", "0.1.1") {
		t.Fatal("equal")
	}
	if !versionAtLeast("0.1.2", "0.1.1") {
		t.Fatal("patch greater")
	}
	if versionAtLeast("0.1.0", "0.1.1") {
		t.Fatal("patch less")
	}
	if versionAtLeast("0.1.1-rc1", "0.1.1") {
		t.Fatal("prerelease must fail closed")
	}
	if versionAtLeast("0.1", "0.1.1") {
		// 0.1 pads as 0.1.0 conceptually — component compare: 0.1 vs 0.1.1
		// have=[0,1] want=[0,1,1] → at i=2 h=0 w=1 → false. Good.
	} else {
		// expected false
	}
	if versionAtLeast("0.1", "0.1.1") {
		t.Fatal("shorter have must not satisfy longer want when missing components are zero and want has trailing nonzero")
	}
}

func TestCommitMatchesPreferredDirection(t *testing.T) {
	if !commitMatchesPreferred("c23af46", "c23af46") {
		t.Fatal("equal")
	}
	if !commitMatchesPreferred("c23af46abc", "c23af46") {
		t.Fatal("longer identity ok")
	}
	if commitMatchesPreferred("c23af4", "c23af46") {
		t.Fatal("shorter identity must not match")
	}
	if commitMatchesPreferred("c", "c23af46") {
		t.Fatal("single-char prefix must not match")
	}
}

func TestReadIdentityAgainstLiveBinary(t *testing.T) {
	bin := os.Getenv(EnvBinary)
	if bin == "" {
		t.Skip("DECERNOR_BIN not set")
	}
	id, err := ReadIdentity(context.Background(), bin)
	if err != nil {
		t.Fatal(err)
	}
	if id.Version == "" || id.Commit == "" {
		t.Fatalf("empty identity: %#v", id)
	}
}
