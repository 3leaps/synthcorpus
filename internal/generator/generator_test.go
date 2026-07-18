package generator

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/3leaps/synthcorpus/internal/guardrail"
)

type recordedCall struct {
	name  string
	args  []string
	env   []string
	stdin string
}

type recordingRunner struct {
	calls      []recordedCall
	failOnName string
	failOnArgs string // substring match in joined args; optional
	// onBeforeName/onBefore run once before the named sidecar call — used to
	// plant TOCTOU destinations at final during the mint window.
	onBeforeName string
	onBefore     func()
	onBeforeDone bool
}

func (r *recordingRunner) Run(ctx context.Context, name string, args []string, env []string, stdin string) error {
	_, err := r.Output(ctx, name, args, env, stdin)
	return err
}

func (r *recordingRunner) Output(_ context.Context, name string, args []string, env []string, stdin string) (string, error) {
	if r.onBefore != nil && !r.onBeforeDone && r.onBeforeName != "" && name == r.onBeforeName {
		r.onBefore()
		r.onBeforeDone = true
	}
	r.calls = append(r.calls, recordedCall{
		name:  name,
		args:  slices.Clone(args),
		env:   slices.Clone(env),
		stdin: stdin,
	})
	if r.failOnName != "" && name == r.failOnName {
		if r.failOnArgs == "" || strings.Contains(strings.Join(args, " "), r.failOnArgs) {
			return "", fmt.Errorf("injected failure for %s", name)
		}
	}
	if name == "gpgconf" {
		return "", nil
	}
	if name == "gpg" && slices.Contains(args, "--list-secret-keys") {
		return strings.Join([]string{
			"sec:-:255:22:AAAAAAAA:0:0:0:::",
			"fpr:::::::::AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:",
			"uid:::::::::synthcorpus generated-real TEST KEY - DO NOT USE <synthcorpus-test@example.invalid>:",
			"sec:-:255:22:BBBBBBBB:0:0:0:::",
			"fpr:::::::::BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB:",
			"uid:::::::::synthcorpus generated-real TEST KEY - DO NOT USE plain <plain.synthcorpus-test@example.invalid>:",
		}, "\n"), nil
	}
	if name == "gpg" && slices.Contains(args, "--generate-key") {
		gnupgHome := envValue(env, "GNUPGHOME")
		revocations := filepath.Join(gnupgHome, "openpgp-revocs.d")
		if err := os.MkdirAll(revocations, 0o700); err != nil {
			return "", err
		}
		if err := os.WriteFile(filepath.Join(revocations, "test.rev"), []byte("test revocation\n"), 0o600); err != nil {
			return "", err
		}
	}
	for _, arg := range outputArgs(name, args) {
		if err := os.MkdirAll(filepath.Dir(arg), 0o700); err != nil {
			return "", err
		}
		body := "test artifact\n"
		if name == "minisign" {
			body = "untrusted comment: minisign default test comment\nencoded-test-artifact\n"
		}
		if err := os.WriteFile(arg, []byte(body), 0o600); err != nil {
			return "", err
		}
	}
	return "", nil
}

func TestGenerateUsesGuardedLayoutAndExplicitSidecarCalls(t *testing.T) {
	t.Setenv("HOME", "/tmp/synthcorpus-test-home")
	t.Setenv("PATH", "/usr/bin:/bin")
	t.Setenv("TMPDIR", "/tmp")
	t.Setenv("GNUPGHOME", "/tmp/user-gnupg-that-must-not-leak")
	t.Setenv("GPG_AGENT_INFO", "/tmp/user-agent-that-must-not-leak")

	root := filepath.Join(t.TempDir(), "dogfooding", "decernor")
	runner := &recordingRunner{}

	err := Generate(context.Background(), Options{
		Tool:      "decernor",
		Out:       root,
		Runner:    runner,
		Preflight: func(context.Context) error { return nil },
		Now:       func() time.Time { return time.Date(2026, 7, 5, 18, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatalf("EvalSymlinks output root: %v", err)
	}

	// No leftover staging dirs next to the final root.
	parent := filepath.Dir(realRoot)
	entries, err := os.ReadDir(parent)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if isStagingDirName(e.Name()) {
			t.Fatalf("leftover staging directory after success: %s", e.Name())
		}
	}

	for _, path := range []string{
		".synthcorpus-generated-real.json",
		"README.md",
		"MANIFEST.json",
		".gnupg",
		"gpg",
		"minisign",
		"ssh",
		"malformed",
	} {
		if _, err := os.Stat(filepath.Join(realRoot, path)); err != nil {
			t.Fatalf("expected %s: %v", path, err)
		}
	}

	if len(runner.calls) == 0 {
		t.Fatalf("expected sidecar calls")
	}
	// Mint runs in a staging directory (renamed to final on success), so
	// GNUPGHOME is under .sc-stg-* during sidecar calls (never the user default).
	for _, call := range runner.calls {
		if call.name == "" {
			t.Fatalf("empty sidecar name")
		}
		if call.name == "gpgconf" {
			continue
		}
		if len(call.args) == 0 {
			t.Fatalf("expected arg-vector call for %s", call.name)
		}
		gnupg := envValue(call.env, "GNUPGHOME")
		if gnupg == "" || filepath.Base(gnupg) != ".gnupg" {
			t.Fatalf("call %s missing isolated GNUPGHOME: %#v", call.name, call.env)
		}
		if !strings.Contains(gnupg, stagingDirPrefix) {
			t.Fatalf("call %s GNUPGHOME should be under staging root during mint: %q", call.name, gnupg)
		}
		if envContainsPrefix(call.env, "GNUPGHOME=/tmp/user-gnupg-that-must-not-leak") {
			t.Fatalf("call %s leaked user GNUPGHOME: %#v", call.name, call.env)
		}
	}

	protectedFP := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	plainFP := "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
	var sawExportProtected, sawExportPlain, sawSign, sawBundledPublic bool
	for _, call := range runner.calls {
		if call.name != "gpg" {
			continue
		}
		if slices.Contains(call.args, "--export") && !slices.Contains(call.args, "--export-secret-keys") {
			// Multi-key public.asc bundle (both FPs) — intentional dogfood breadth.
			if slices.Contains(call.args, protectedFP) && slices.Contains(call.args, plainFP) {
				sawBundledPublic = true
			}
		}
		if slices.Contains(call.args, "--export-secret-keys") {
			if slices.Contains(call.args, protectedFP) && !slices.Contains(call.args, plainFP) {
				sawExportProtected = true
			}
			if slices.Contains(call.args, plainFP) && !slices.Contains(call.args, protectedFP) {
				sawExportPlain = true
			}
			for _, a := range call.args {
				if strings.Contains(a, "@") {
					t.Fatalf("export-secret-keys used email selector %q", a)
				}
			}
		}
		if slices.Contains(call.args, "--detach-sign") {
			if !slices.Contains(call.args, protectedFP) {
				t.Fatalf("detach-sign must use protected fingerprint, got %#v", call.args)
			}
			sawSign = true
		}
	}
	if !sawExportProtected || !sawExportPlain || !sawSign || !sawBundledPublic {
		t.Fatalf("fingerprint export/sign incomplete; protected=%v plain=%v sign=%v publicBundle=%v", sawExportProtected, sawExportPlain, sawSign, sawBundledPublic)
	}

	// MANIFEST class for public.asc must be public-bundle (multi-key), not bare public.
	manifestBody, err := os.ReadFile(filepath.Join(realRoot, "MANIFEST.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(manifestBody), `"class": "public-bundle"`) {
		t.Fatalf("MANIFEST missing public-bundle class: %s", manifestBody)
	}
	if strings.Contains(string(manifestBody), `"path": "gpg/public.asc"`) &&
		!strings.Contains(string(manifestBody), `"class": "public-bundle"`) {
		t.Fatal("public.asc not labeled public-bundle")
	}

	for _, path := range []string{
		"gpg/private-protected.asc",
		"minisign/minisign-protected.key",
		"ssh/id_ed25519_protected",
	} {
		info, err := os.Stat(filepath.Join(realRoot, path))
		if err != nil {
			t.Fatalf("stat %s: %v", path, err)
		}
		if got := info.Mode().Perm(); got != 0o600 {
			t.Fatalf("%s mode = %o, want 0600", path, got)
		}
	}
}

func TestGenerateCleansStagingOnInjectedFailures(t *testing.T) {
	cases := []struct {
		name       string
		failOnName string
		failOnArgs string
	}{
		{"gpgconf", "gpgconf", ""},
		{"gpg-generate", "gpg", "--generate-key"},
		{"minisign", "minisign", ""},
		{"ssh-keygen", "ssh-keygen", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			parent := t.TempDir()
			final := filepath.Join(parent, "decernor")
			runner := &recordingRunner{failOnName: tc.failOnName, failOnArgs: tc.failOnArgs}
			err := Generate(context.Background(), Options{
				Tool:      "decernor",
				Out:       final,
				Runner:    runner,
				Preflight: func(context.Context) error { return nil },
			})
			if err == nil {
				t.Fatal("expected injected failure")
			}
			if _, err := os.Stat(final); !os.IsNotExist(err) {
				t.Fatalf("final corpus must not exist after failed mint: %v", err)
			}
			assertNoStagingOrBackup(t, parent)
		})
	}
}

func TestGenerateForcePreservesPriorCorpusUntilSuccess(t *testing.T) {
	parent := t.TempDir()
	final := filepath.Join(parent, "decernor")

	// First successful mint.
	if err := Generate(context.Background(), Options{
		Tool:      "decernor",
		Out:       final,
		Runner:    &recordingRunner{},
		Preflight: func(context.Context) error { return nil },
	}); err != nil {
		t.Fatalf("initial generate: %v", err)
	}
	sentinel := filepath.Join(final, "prior-sentinel.txt")
	if err := os.WriteFile(sentinel, []byte("prior\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Force with mid-mint failure must restore/keep prior corpus content.
	err := Generate(context.Background(), Options{
		Tool:      "decernor",
		Out:       final,
		Force:     true,
		Runner:    &recordingRunner{failOnName: "minisign"},
		Preflight: func(context.Context) error { return nil },
	})
	if err == nil {
		t.Fatal("expected force remint failure")
	}
	data, err := os.ReadFile(sentinel)
	if err != nil {
		t.Fatalf("prior corpus lost after failed force remint: %v", err)
	}
	if string(data) != "prior\n" {
		t.Fatalf("prior corpus corrupted: %q", data)
	}
	assertNoStagingOrBackup(t, parent)
}

func TestPublishRefusesNonForceFinalPlantedDuringMint(t *testing.T) {
	// Destination was absent at start; during mint an unowned final appears.
	// Publish must fail without moving/removing the sentinel.
	parent := t.TempDir()
	final := filepath.Join(parent, "decernor")
	// Resolve early so the planted path matches Generate's canonical final.
	resolvedFinal, err := guardrail.ResolveOutputPath(final)
	if err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(resolvedFinal, "unowned-sentinel.txt")

	runner := &recordingRunner{
		onBeforeName: "minisign",
		onBefore: func() {
			if err := os.MkdirAll(resolvedFinal, 0o700); err != nil {
				t.Errorf("plant final: %v", err)
				return
			}
			if err := os.WriteFile(sentinel, []byte("do-not-clobber\n"), 0o600); err != nil {
				t.Errorf("plant sentinel: %v", err)
			}
		},
	}
	err = Generate(context.Background(), Options{
		Tool:      "decernor",
		Out:       final,
		Force:     false,
		Runner:    runner,
		Preflight: func(context.Context) error { return nil },
	})
	if err == nil || !strings.Contains(err.Error(), "publish destination re-check") {
		t.Fatalf("expected publish re-check failure, got %v", err)
	}
	data, err := os.ReadFile(sentinel)
	if err != nil {
		t.Fatalf("sentinel was moved/removed: %v", err)
	}
	if string(data) != "do-not-clobber\n" {
		t.Fatalf("sentinel corrupted: %q", data)
	}
	// Staging cleaned; no backup of the unowned dir.
	assertNoStagingOrBackup(t, filepath.Dir(resolvedFinal))
}

func TestPublishRefusesForceWhenMarkerLostDuringMint(t *testing.T) {
	// Start with a marker-owned force-eligible corpus; during mint replace it
	// with an unowned directory. Publish must not clobber the unowned path.
	parent := t.TempDir()
	final := filepath.Join(parent, "decernor")
	if err := Generate(context.Background(), Options{
		Tool:      "decernor",
		Out:       final,
		Runner:    &recordingRunner{},
		Preflight: func(context.Context) error { return nil },
	}); err != nil {
		t.Fatalf("initial mint: %v", err)
	}
	realFinal, err := filepath.EvalSymlinks(final)
	if err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(realFinal, "unowned-after-replace.txt")

	runner := &recordingRunner{
		onBeforeName: "minisign",
		onBefore: func() {
			// Replace marker-owned corpus with unowned content at the same path.
			if err := os.RemoveAll(realFinal); err != nil {
				t.Errorf("remove prior: %v", err)
				return
			}
			if err := os.MkdirAll(realFinal, 0o700); err != nil {
				t.Errorf("recreate unowned: %v", err)
				return
			}
			if err := os.WriteFile(sentinel, []byte("unowned\n"), 0o600); err != nil {
				t.Errorf("plant unowned sentinel: %v", err)
			}
		},
	}
	err = Generate(context.Background(), Options{
		Tool:      "decernor",
		Out:       final,
		Force:     true,
		Runner:    runner,
		Preflight: func(context.Context) error { return nil },
	})
	if err == nil || !strings.Contains(err.Error(), "publish destination re-check") {
		t.Fatalf("expected publish re-check failure after marker loss, got %v", err)
	}
	data, err := os.ReadFile(sentinel)
	if err != nil {
		t.Fatalf("unowned sentinel was moved/removed: %v", err)
	}
	if string(data) != "unowned\n" {
		t.Fatalf("unowned sentinel corrupted: %q", data)
	}
	assertNoStagingOrBackup(t, filepath.Dir(realFinal))
}

func TestGenerateForceSuccessRemovesBackup(t *testing.T) {
	parent := t.TempDir()
	final := filepath.Join(parent, "decernor")
	if err := Generate(context.Background(), Options{
		Tool:      "decernor",
		Out:       final,
		Runner:    &recordingRunner{},
		Preflight: func(context.Context) error { return nil },
	}); err != nil {
		t.Fatalf("initial: %v", err)
	}
	if err := Generate(context.Background(), Options{
		Tool:      "decernor",
		Out:       final,
		Force:     true,
		Runner:    &recordingRunner{},
		Preflight: func(context.Context) error { return nil },
	}); err != nil {
		t.Fatalf("force remint: %v", err)
	}
	if _, err := os.Stat(filepath.Join(final, "MANIFEST.json")); err != nil {
		t.Fatalf("final corpus missing after force success: %v", err)
	}
	assertNoStagingOrBackup(t, parent)
}

func TestGeneratePublishRenameFailureRestoresPrior(t *testing.T) {
	parent := t.TempDir()
	final := filepath.Join(parent, "decernor")
	if err := Generate(context.Background(), Options{
		Tool:      "decernor",
		Out:       final,
		Runner:    &recordingRunner{},
		Preflight: func(context.Context) error { return nil },
	}); err != nil {
		t.Fatalf("initial: %v", err)
	}
	realFinal, err := filepath.EvalSymlinks(final)
	if err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(realFinal, "prior-sentinel.txt")
	if err := os.WriteFile(sentinel, []byte("prior\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	origRename := rename
	t.Cleanup(func() { rename = origRename })
	// Fail only the staging→final publish rename (after prior was moved to backup).
	// Compare against realpath: ResolveOutputPath canonicalizes on macOS.
	rename = func(oldpath, newpath string) error {
		if isStagingDirName(filepath.Base(oldpath)) && newpath == realFinal {
			return errors.New("injected publish rename failure")
		}
		return origRename(oldpath, newpath)
	}

	err = Generate(context.Background(), Options{
		Tool:      "decernor",
		Out:       final,
		Force:     true,
		Runner:    &recordingRunner{},
		Preflight: func(context.Context) error { return nil },
	})
	if err == nil || !strings.Contains(err.Error(), "publish staged corpus") {
		t.Fatalf("expected publish failure, got %v", err)
	}
	data, err := os.ReadFile(sentinel)
	if err != nil {
		t.Fatalf("prior corpus not restored: %v", err)
	}
	if string(data) != "prior\n" {
		t.Fatalf("restored corpus wrong content: %q", data)
	}
	// Parent of realFinal for leftover check (may be /private/tmp/...).
	assertNoStagingOrBackup(t, filepath.Dir(realFinal))
}

func TestGenerateSurfacesStagingCleanupFailure(t *testing.T) {
	parent := t.TempDir()
	final := filepath.Join(parent, "decernor")
	origRemove := removeAll
	t.Cleanup(func() { removeAll = origRemove })

	var residual string
	removeAll = func(path string) error {
		if isStagingDirName(filepath.Base(path)) {
			residual = path
			return errors.New("injected staging cleanup failure")
		}
		return origRemove(path)
	}

	err := Generate(context.Background(), Options{
		Tool:      "decernor",
		Out:       final,
		Runner:    &recordingRunner{failOnName: "minisign"},
		Preflight: func(context.Context) error { return nil },
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "injected failure for minisign") {
		t.Fatalf("original mint error lost: %v", err)
	}
	if !strings.Contains(err.Error(), "failed to remove staging") && !strings.Contains(err.Error(), "also failed to remove staging") {
		t.Fatalf("cleanup failure not surfaced: %v", err)
	}
	if residual == "" {
		t.Fatal("expected cleanup to target a staging path")
	}
	// Residual intentionally remains because cleanup was injected to fail.
	if _, err := os.Stat(residual); err != nil {
		t.Fatalf("expected residual staging path for operator visibility: %v", err)
	}
	// Final must still be absent (never published).
	if _, err := os.Stat(final); !os.IsNotExist(err) {
		t.Fatalf("final must not exist: %v", err)
	}
	// Clean residual so TempDir teardown is quiet.
	_ = origRemove(residual)
}

func TestGenerateDeepPathGPGConfFailureLeavesNoCorpus(t *testing.T) {
	// Build a path deep enough that GNUPGHOME would exceed the macOS socket
	// budget without socketdir — gpgconf failure must happen before mint and
	// leave neither final nor residual staging.
	parent := t.TempDir()
	deep := parent
	for i := 0; i < 8; i++ {
		deep = filepath.Join(deep, strings.Repeat("d", 20))
	}
	final := filepath.Join(deep, "decernor")
	err := Generate(context.Background(), Options{
		Tool:      "decernor",
		Out:       final,
		Runner:    &recordingRunner{failOnName: "gpgconf"},
		Preflight: func(context.Context) error { return nil },
	})
	if err == nil {
		t.Fatal("expected gpgconf failure on deep path")
	}
	if !strings.Contains(err.Error(), "gpgconf") && !strings.Contains(err.Error(), "socket") && !strings.Contains(err.Error(), "injected failure") {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := os.Stat(final); !os.IsNotExist(err) {
		t.Fatalf("final must be absent: %v", err)
	}
	// Walk parent for any staging residue under the deep tree.
	_ = filepath.WalkDir(parent, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		name := d.Name()
		if isStagingDirName(name) || strings.Contains(name, ".synthcorpus-backup-") {
			t.Errorf("leftover after deep-path failure: %s", path)
		}
		return nil
	})
}

func assertNoStagingOrBackup(t *testing.T, parent string) {
	t.Helper()
	entries, err := os.ReadDir(parent)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		name := e.Name()
		// Staging: .sc-stg-* (legacy .synthcorpus-staging-* also recognized)
		// Backup of final "decernor": decernor.synthcorpus-backup-<pid>
		if isStagingDirName(name) || strings.Contains(name, ".synthcorpus-backup-") {
			t.Fatalf("leftover %s under %s", name, parent)
		}
	}
}

func TestStagingDirNameKeepsDogfoodGPGHomeInBudget(t *testing.T) {
	// Representative length of a shallow dogfood parent such as
	// $HOME/dev/dogfooding on common layouts (34 characters). Synthetic only —
	// do not embed real workstation paths in committed tests.
	const representativeDogfoodParentLen = 34
	parent := strings.Repeat("d", representativeDogfoodParentLen)
	name := stagingDirName(time.Date(2026, 7, 18, 15, 0, 0, 123456789, time.UTC), 87800)
	if !strings.HasPrefix(name, stagingDirPrefix) {
		t.Fatalf("prefix = %q", name)
	}
	if len(name) > 24 {
		t.Fatalf("staging name too long: %q (len=%d)", name, len(name))
	}
	home := filepath.Join(parent, name, ".gnupg")
	if len(home) > maxGNUPGHomeWithoutSocketdir {
		t.Fatalf("dogfood staging GNUPGHOME still over budget: len=%d > %d (name=%q)", len(home), maxGNUPGHomeWithoutSocketdir, name)
	}
	// Historical long form must exceed the budget (regression anchor).
	legacy := filepath.Join(parent, fmt.Sprintf(".synthcorpus-staging-%d-%d", 87800, 1784388756546086000), ".gnupg")
	if len(legacy) <= maxGNUPGHomeWithoutSocketdir {
		t.Fatalf("legacy staging unexpectedly fits budget (len=%d); update regression anchor", len(legacy))
	}
}

func TestGenerateChmodFailureCleansStaging(t *testing.T) {
	parent := t.TempDir()
	final := filepath.Join(parent, "decernor")
	orig := chmodImpl
	t.Cleanup(func() { chmodImpl = orig })
	chmodImpl = func(path string, mode os.FileMode) error {
		if strings.Contains(path, "private-protected") || strings.HasSuffix(path, "minisign-protected.key") {
			return errors.New("injected chmod failure")
		}
		return orig(path, mode)
	}

	err := Generate(context.Background(), Options{
		Tool:      "decernor",
		Out:       final,
		Runner:    &recordingRunner{},
		Preflight: func(context.Context) error { return nil },
	})
	if err == nil {
		t.Fatal("expected chmod failure")
	}
	if _, err := os.Stat(final); !os.IsNotExist(err) {
		t.Fatalf("final must be absent after chmod failure: %v", err)
	}
}

func TestGenerateRunsPreflightBeforeOutputMutation(t *testing.T) {
	root := filepath.Join(t.TempDir(), "dogfood")
	preflightCalled := false
	err := Generate(context.Background(), Options{
		Tool:   "decernor",
		Out:    root,
		Runner: &recordingRunner{},
		Preflight: func(context.Context) error {
			preflightCalled = true
			if _, err := os.Stat(root); !os.IsNotExist(err) {
				t.Fatalf("output root mutated before preflight completed: %v", err)
			}
			// staging parent also must not yet hold staging dirs
			return nil
		},
	})
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}
	if !preflightCalled {
		t.Fatal("expected preflight to run")
	}
}

func TestGenerateFailsClosedOnPreflightError(t *testing.T) {
	root := filepath.Join(t.TempDir(), "dogfood")
	err := Generate(context.Background(), Options{
		Tool:   "decernor",
		Out:    root,
		Runner: &recordingRunner{},
		Preflight: func(context.Context) error {
			return context.Canceled
		},
	})
	if err == nil {
		t.Fatal("expected preflight failure")
	}
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatalf("output root must not be created when preflight fails: %v", err)
	}
}

func TestParseColonFingerprintsExactEmail(t *testing.T) {
	out := strings.Join([]string{
		"sec:-:255:22:AAAAAAAA:0:0:0:::",
		"fpr:::::::::AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:",
		"uid:::::::::Name <synthcorpus-test@example.invalid>:",
		"ssb:-:255:22:SUBKEYID:0:0:0:::",
		"fpr:::::::::CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC:",
		"sec:-:255:22:BBBBBBBB:0:0:0:::",
		"fpr:::::::::BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB:",
		"uid:::::::::Name plain <plain.synthcorpus-test@example.invalid>:",
	}, "\n")
	keys, err := parseColonFingerprints(out)
	if err != nil {
		t.Fatal(err)
	}
	protected, err := fingerprintForEmail(keys, "synthcorpus-test@example.invalid")
	if err != nil || protected != "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" {
		t.Fatalf("protected fp = %q err=%v", protected, err)
	}
	plain, err := fingerprintForEmail(keys, "plain.synthcorpus-test@example.invalid")
	if err != nil || plain != "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB" {
		t.Fatalf("plain fp = %q err=%v", plain, err)
	}
}

func TestParseGPGVersion(t *testing.T) {
	ver, err := parseGPGVersion("gpg (GnuPG) 2.4.5\nlibgcrypt 1.10\n")
	if err != nil {
		t.Fatal(err)
	}
	if !versionAtLeast(ver, [3]int{2, 4, 0}) {
		t.Fatalf("expected 2.4.5 >= 2.4.0")
	}
	old, err := parseGPGVersion("gpg (GnuPG) 2.2.27\n")
	if err != nil {
		t.Fatal(err)
	}
	if versionAtLeast(old, [3]int{2, 4, 0}) {
		t.Fatalf("2.2.27 must not satisfy 2.4.0")
	}
}

func TestRunSidecarPreflightProbesAllHelpers(t *testing.T) {
	bin := t.TempDir()
	writeFake(t, bin, "gpg", "#!/bin/sh\necho 'gpg (GnuPG) 2.4.5'\n")
	writeFake(t, bin, "gpgconf", "#!/bin/sh\necho 'gpgconf (GnuPG) 2.4.5'\n")
	writeFake(t, bin, "minisign", "#!/bin/sh\necho 'minisign 0.11'\n")
	// Non-interactive OpenSSH-shaped response to -t <invalid>.
	writeFake(t, bin, "ssh-keygen", "#!/bin/sh\necho \"unknown key type $2\"\nexit 1\n")

	probe := SidecarProbe{
		LookPath: func(file string) (string, error) {
			p := filepath.Join(bin, file)
			if _, err := os.Stat(p); err != nil {
				return "", err
			}
			return p, nil
		},
		Run: func(ctx context.Context, path string, args ...string) (string, error) {
			return defaultSidecarProbe().Run(ctx, path, args...)
		},
	}
	if err := RunSidecarPreflight(context.Background(), probe); err != nil {
		t.Fatalf("expected preflight success with capable fakes: %v", err)
	}
}

func TestProbeSSHKeygenRejectsInteractiveAndAcceptsInvalidType(t *testing.T) {
	t.Run("rejects-interactive", func(t *testing.T) {
		err := probeSSHKeygen(context.Background(), SidecarProbe{
			Run: func(context.Context, string, ...string) (string, error) {
				return "Generating public/private ed25519 key pair.\nEnter file in which to save the key (/tmp/id):", errors.New("exit 1")
			},
		}, "/usr/bin/ssh-keygen")
		if err == nil || !strings.Contains(err.Error(), "interactive") {
			t.Fatalf("expected interactive rejection, got %v", err)
		}
	})
	t.Run("accepts-unknown-key-type", func(t *testing.T) {
		err := probeSSHKeygen(context.Background(), SidecarProbe{
			Run: func(_ context.Context, _ string, args ...string) (string, error) {
				if len(args) < 2 || args[0] != "-t" {
					t.Fatalf("expected -t probe, got %#v", args)
				}
				return "unknown key type " + args[1], errors.New("exit 1")
			},
		}, "/usr/bin/ssh-keygen")
		if err != nil {
			t.Fatalf("expected accept: %v", err)
		}
	})
	t.Run("host-binary-noninteractive", func(t *testing.T) {
		path, err := exec.LookPath("ssh-keygen")
		if err != nil {
			t.Skip("ssh-keygen not on PATH")
		}
		if err := probeSSHKeygen(context.Background(), defaultSidecarProbe(), path); err != nil {
			t.Fatalf("host ssh-keygen preflight failed: %v", err)
		}
	})
}

func TestRunSidecarPreflightRejectsMissingBrokenAndOldGPG(t *testing.T) {
	t.Run("missing", func(t *testing.T) {
		err := RunSidecarPreflight(context.Background(), SidecarProbe{
			LookPath: func(string) (string, error) { return "", os.ErrNotExist },
			Run:      func(context.Context, string, ...string) (string, error) { return "", nil },
		})
		if err == nil || !strings.Contains(err.Error(), "not found") {
			t.Fatalf("expected missing sidecar error, got %v", err)
		}
	})
	t.Run("old-gpg", func(t *testing.T) {
		err := RunSidecarPreflight(context.Background(), SidecarProbe{
			LookPath: func(name string) (string, error) { return "/bin/" + name, nil },
			Run: func(_ context.Context, path string, args ...string) (string, error) {
				base := filepath.Base(path)
				switch base {
				case "gpg":
					return "gpg (GnuPG) 2.2.27\n", nil
				case "gpgconf":
					return "gpgconf (GnuPG) 2.2.27\n", nil
				case "minisign":
					return "minisign 0.11\n", nil
				case "ssh-keygen":
					return "unknown key type x\n", fmt.Errorf("exit 1")
				default:
					return "", fmt.Errorf("unexpected %s", path)
				}
			},
		})
		if err == nil || !strings.Contains(err.Error(), "2.4.0") {
			t.Fatalf("expected gpg minimum version error, got %v", err)
		}
	})
	t.Run("broken-minisign", func(t *testing.T) {
		err := RunSidecarPreflight(context.Background(), SidecarProbe{
			LookPath: func(name string) (string, error) { return "/bin/" + name, nil },
			Run: func(_ context.Context, path string, args ...string) (string, error) {
				base := filepath.Base(path)
				switch base {
				case "gpg":
					return "gpg (GnuPG) 2.4.5\n", nil
				case "gpgconf":
					return "gpgconf (GnuPG) 2.4.5\n", nil
				case "minisign":
					return "exec format error", errors.New("exec format error")
				default:
					return "unknown key type x", fmt.Errorf("exit 1")
				}
			},
		})
		if err == nil || !strings.Contains(err.Error(), "minisign") {
			t.Fatalf("expected minisign probe failure, got %v", err)
		}
	})
}

func writeFake(t *testing.T, dir, name, body string) {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
}

func outputArgs(name string, args []string) []string {
	var out []string
	switch name {
	case "gpg":
		for i := 0; i < len(args)-1; i++ {
			if args[i] == "--output" {
				out = append(out, args[i+1])
			}
		}
	case "minisign":
		if slices.Contains(args, "-G") {
			for i := 0; i < len(args)-1; i++ {
				if args[i] == "-p" || args[i] == "-s" {
					out = append(out, args[i+1])
				}
			}
		}
		if slices.Contains(args, "-S") {
			for i := 0; i < len(args)-1; i++ {
				if args[i] == "-x" {
					out = append(out, args[i+1])
				}
			}
		}
	case "ssh-keygen":
		for i := 0; i < len(args)-1; i++ {
			if args[i] == "-f" {
				out = append(out, args[i+1], args[i+1]+".pub")
			}
		}
	}
	return out
}

func envContainsPrefix(env []string, prefix string) bool {
	for _, item := range env {
		if item == prefix {
			return true
		}
	}
	return false
}

func envValue(env []string, key string) string {
	prefix := key + "="
	for _, item := range env {
		if strings.HasPrefix(item, prefix) {
			return strings.TrimPrefix(item, prefix)
		}
	}
	return ""
}
