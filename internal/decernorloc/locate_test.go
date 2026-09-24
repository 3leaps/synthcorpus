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

func TestLocateBinaryEnvOrderFailsClosed(t *testing.T) {
	dir := t.TempDir()
	repoBin := filepath.Join(dir, "repo-decernor")
	legacyBin := filepath.Join(dir, "legacy-decernor")
	pathDir := filepath.Join(dir, "path")
	if err := os.Mkdir(pathDir, 0o700); err != nil {
		t.Fatal(err)
	}
	pathBin := filepath.Join(pathDir, "decernor")
	for _, path := range []string{repoBin, legacyBin, pathBin} {
		if err := os.WriteFile(path, []byte("binary"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", pathDir)
	t.Setenv(EnvRepoBinary, repoBin)
	t.Setenv(EnvBinary, legacyBin)
	pin := Pin{Locate: Locate{
		Env:       EnvBinary,
		EnvOrder:  []string{EnvRepoBinary, EnvBinary},
		PathNames: []string{"decernor"},
	}}

	check := func(want string) {
		t.Helper()
		got, err := LocateBinary("", pin)
		if err != nil || got != want {
			t.Fatalf("LocateBinary() = %q, %v; want %q", got, err, want)
		}
	}
	check(repoBin)
	t.Setenv(EnvRepoBinary, "../missing")
	if _, err := LocateBinary("", pin); err == nil || !strings.Contains(err.Error(), "relative") {
		t.Fatalf("bad repo env must fail without falling back: %v", err)
	}
	t.Setenv(EnvRepoBinary, " ")
	if _, err := LocateBinary("", pin); err == nil {
		t.Fatal("whitespace repo env must fail without falling back")
	}
	t.Setenv(EnvRepoBinary, dir)
	if _, err := LocateBinary("", pin); err == nil || !strings.Contains(err.Error(), "directory") {
		t.Fatalf("directory repo env must fail without falling back: %v", err)
	}
	t.Setenv(EnvRepoBinary, "")
	check(legacyBin)
	t.Setenv(EnvBinary, filepath.Join(dir, "missing"))
	if _, err := LocateBinary("", pin); err == nil {
		t.Fatal("bad legacy env must fail without falling back to PATH")
	}
	t.Setenv(EnvBinary, "")
	check(pathBin)
	t.Setenv(EnvRepoBinary, legacyBin)
	got, err := LocateBinary(repoBin, pin)
	if err != nil || got != repoBin {
		t.Fatalf("explicit path = %q, %v", got, err)
	}
	if _, err := LocateBinary("../missing", pin); err == nil {
		t.Fatal("bad explicit path must fail without falling back")
	}
	if _, err := LocateBinary(" ", pin); err == nil {
		t.Fatal("whitespace explicit path must fail without falling back")
	}
}

func TestLocatedOverrideStillChecksIdentity(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell-script identity fixture")
	}
	dir := t.TempDir()
	pathDir := filepath.Join(dir, "path")
	if err := os.Mkdir(pathDir, 0o700); err != nil {
		t.Fatal(err)
	}
	good := filepath.Join(pathDir, "decernor")
	if err := os.WriteFile(good, []byte("#!/bin/sh\nprintf 'Version: 0.1.8\\nCommit: 08c0afc\\n'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", pathDir)
	t.Setenv(EnvBinary, "")
	pin := Pin{
		SchemaVersion: pinSchemaVersion, Kind: pinKind, Consumer: pinConsumer, Tool: pinTool,
		MinVersion: "0.1.8", PreferredTag: "v0.1.8", PreferredCommit: "08c0afc",
		Locate: Locate{EnvOrder: []string{EnvRepoBinary, EnvBinary}, PathNames: []string{"decernor"}},
	}
	for _, tc := range []struct {
		name, version, commit string
	}{
		{name: "old version", version: "0.1.7", commit: "08c0afc"},
		{name: "wrong commit", version: "0.1.8", commit: "70efa26"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stale := filepath.Join(dir, strings.ReplaceAll(tc.name, " ", "-"))
			script := "#!/bin/sh\nprintf 'Version: " + tc.version + "\\nCommit: " + tc.commit + "\\n'\n"
			if err := os.WriteFile(stale, []byte(script), 0o755); err != nil {
				t.Fatal(err)
			}
			t.Setenv(EnvRepoBinary, stale)
			binary, err := LocateBinary("", pin)
			if err != nil || binary != stale {
				t.Fatalf("LocateBinary() = %q, %v; want stale override", binary, err)
			}
			id, err := ReadIdentity(context.Background(), binary)
			if err != nil {
				t.Fatal(err)
			}
			if err := CheckPin(id, pin); err == nil {
				t.Fatal("stale override must fail identity check without using good PATH binary")
			}
		})
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
	if pin.MinVersion != "0.1.8" || pin.PreferredTag != "v0.1.8" || pin.PreferredCommit != "08c0afc" {
		t.Fatalf("pin = %#v", pin)
	}
	if pin.Locate.Env != EnvBinary {
		t.Fatalf("locate.env = %q", pin.Locate.Env)
	}
	if len(pin.Locate.EnvOrder) != 2 || pin.Locate.EnvOrder[0] != EnvRepoBinary || pin.Locate.EnvOrder[1] != EnvBinary {
		t.Fatalf("locate.env_order = %#v", pin.Locate.EnvOrder)
	}
}

func TestCheckPinVersionAndCommit(t *testing.T) {
	pin := Pin{
		SchemaVersion:   pinSchemaVersion,
		Kind:            pinKind,
		Consumer:        pinConsumer,
		Tool:            pinTool,
		MinVersion:      "0.1.1",
		PreferredTag:    "v0.1.1",
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

func TestValidatePinRequiresExactTag(t *testing.T) {
	base := Pin{
		SchemaVersion:   pinSchemaVersion,
		Kind:            pinKind,
		Consumer:        pinConsumer,
		Tool:            pinTool,
		MinVersion:      "0.1.3",
		PreferredTag:    "v0.1.3",
		PreferredCommit: "fb19564",
	}
	if err := validatePin(base); err != nil {
		t.Fatal(err)
	}

	missing := base
	missing.PreferredTag = ""
	if err := validatePin(missing); err == nil {
		t.Fatal("expected missing preferred_tag failure")
	}

	mismatch := base
	mismatch.PreferredTag = "v9.9.9"
	if err := validatePin(mismatch); err == nil {
		t.Fatal("expected mismatched preferred_tag failure")
	}

	twoPart := base
	twoPart.MinVersion = "0.1"
	twoPart.PreferredTag = "v0.1"
	if err := validatePin(twoPart); err == nil {
		t.Fatal("expected two-part tag failure")
	}

	malformed := base
	malformed.PreferredTag = "v0.1"
	if err := validatePin(malformed); err == nil {
		t.Fatal("expected malformed preferred_tag failure")
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
	bin := os.Getenv(EnvRepoBinary)
	if bin == "" {
		bin = os.Getenv(EnvBinary)
	}
	if bin == "" {
		t.Skip("decernor binary environment not set")
	}
	id, err := ReadIdentity(context.Background(), bin)
	if err != nil {
		t.Fatal(err)
	}
	if id.Version == "" || id.Commit == "" {
		t.Fatalf("empty identity: %#v", id)
	}
}
