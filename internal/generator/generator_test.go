package generator

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

type recordedCall struct {
	name  string
	args  []string
	env   []string
	stdin string
}

type recordingRunner struct {
	calls []recordedCall
}

func (r *recordingRunner) Run(ctx context.Context, name string, args []string, env []string, stdin string) error {
	_, err := r.Output(ctx, name, args, env, stdin)
	return err
}

func (r *recordingRunner) Output(_ context.Context, name string, args []string, env []string, stdin string) (string, error) {
	r.calls = append(r.calls, recordedCall{
		name:  name,
		args:  slices.Clone(args),
		env:   slices.Clone(env),
		stdin: stdin,
	})
	if name == "gpgconf" {
		return "", nil
	}
	if name == "gpg" && slices.Contains(args, "--list-secret-keys") {
		// Distinct fingerprints for protected vs plain UIDs — proves selectors
		// use exact FP, not email substrings.
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

	// Guardrail canonicalizes intermediate symlinks (e.g. macOS /var →
	// /private/var); sidecars must bind to the realpath, not the logical input.
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatalf("EvalSymlinks output root: %v", err)
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
	wantGNUPG := "GNUPGHOME=" + filepath.Join(realRoot, ".gnupg")
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
		if !envContainsPrefix(call.env, wantGNUPG) {
			t.Fatalf("call %s missing isolated GNUPGHOME: %#v", call.name, call.env)
		}
		if envContainsPrefix(call.env, "GNUPGHOME=/tmp/user-gnupg-that-must-not-leak") {
			t.Fatalf("call %s leaked user GNUPGHOME: %#v", call.name, call.env)
		}
		if envContainsPrefix(call.env, "GPG_AGENT_INFO=/tmp/user-agent-that-must-not-leak") {
			t.Fatalf("call %s leaked user GPG_AGENT_INFO: %#v", call.name, call.env)
		}
		if !envContainsPrefix(call.env, "HOME=/tmp/synthcorpus-test-home") {
			t.Fatalf("call %s missing runtime HOME: %#v", call.name, call.env)
		}
		if !envContainsPrefix(call.env, "PATH=/usr/bin:/bin") {
			t.Fatalf("call %s missing runtime PATH: %#v", call.name, call.env)
		}
	}

	// GPG export/sign must use exact fingerprints, never email substrings.
	protectedFP := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	plainFP := "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
	var sawExportProtected, sawExportPlain, sawSign bool
	for _, call := range runner.calls {
		if call.name != "gpg" {
			continue
		}
		if slices.Contains(call.args, "--export-secret-keys") {
			if slices.Contains(call.args, protectedFP) && !slices.Contains(call.args, plainFP) && !slices.Contains(call.args, testEmail) {
				sawExportProtected = true
			}
			if slices.Contains(call.args, plainFP) && !slices.Contains(call.args, protectedFP) && !slices.Contains(call.args, "plain."+testEmail) {
				sawExportPlain = true
			}
			for _, a := range call.args {
				if strings.Contains(a, "@") {
					t.Fatalf("export-secret-keys used email selector %q; want exact fingerprint", a)
				}
			}
		}
		if slices.Contains(call.args, "--detach-sign") {
			if !slices.Contains(call.args, "--local-user") || !slices.Contains(call.args, protectedFP) {
				t.Fatalf("detach-sign must use --local-user <protected fingerprint>, got %#v", call.args)
			}
			for _, a := range call.args {
				if strings.Contains(a, "@") {
					t.Fatalf("detach-sign used email selector %q; want exact fingerprint", a)
				}
			}
			sawSign = true
		}
	}
	if !sawExportProtected || !sawExportPlain || !sawSign {
		t.Fatalf("expected fingerprint-exact export/sign calls; protected=%v plain=%v sign=%v calls=%#v", sawExportProtected, sawExportPlain, sawSign, runner.calls)
	}

	hasGPG := false
	hasMinisign := false
	hasSSH := false
	hasGPGConf := false
	for _, call := range runner.calls {
		hasGPG = hasGPG || call.name == "gpg"
		hasMinisign = hasMinisign || call.name == "minisign"
		hasSSH = hasSSH || call.name == "ssh-keygen"
		hasGPGConf = hasGPGConf || call.name == "gpgconf"
	}
	if !hasGPG || !hasMinisign || !hasSSH || !hasGPGConf {
		t.Fatalf("expected gpg/gpgconf/minisign/ssh-keygen calls; got %#v", runner.calls)
	}

	for _, path := range []string{
		"minisign/minisign-protected.pub",
		"minisign/minisign-protected.key",
		"minisign/minisign-plain.pub",
		"minisign/minisign-plain.key",
	} {
		data, err := os.ReadFile(filepath.Join(realRoot, path))
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		firstLine, _, _ := strings.Cut(string(data), "\n")
		if !strings.Contains(firstLine, "synthcorpus generated-real TEST KEY - DO NOT USE") {
			t.Fatalf("%s first line not stamped as test material: %q", path, firstLine)
		}
	}

	// Fail-closed chmod: secrets 0600, public specimens not world-writable oddly.
	for _, path := range []string{
		"gpg/private-protected.asc",
		"gpg/private-plain.asc",
		"minisign/minisign-protected.key",
		"minisign/minisign-plain.key",
		"ssh/id_ed25519_protected",
		"ssh/id_ed25519_plain",
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

func TestGenerateRunsPreflightBeforeOutputMutation(t *testing.T) {
	root := filepath.Join(t.TempDir(), "dogfood")
	preflightCalled := false
	err := Generate(context.Background(), Options{
		Tool:   "decernor",
		Out:    root,
		Runner: &recordingRunner{},
		Preflight: func(context.Context) error {
			preflightCalled = true
			// Root must not exist yet — preflight is before PrepareOutputRoot.
			if _, err := os.Stat(root); !os.IsNotExist(err) {
				t.Fatalf("output root mutated before preflight completed: %v", err)
			}
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
	// Substring must not match the protected key when looking up plain.
	if _, err := fingerprintForEmail(keys, "plain.synthcorpus-test@example.invalid"); err != nil {
		t.Fatal(err)
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
