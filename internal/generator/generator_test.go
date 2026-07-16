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

func (r *recordingRunner) Run(_ context.Context, name string, args []string, env []string, stdin string) error {
	r.calls = append(r.calls, recordedCall{
		name:  name,
		args:  slices.Clone(args),
		env:   slices.Clone(env),
		stdin: stdin,
	})
	if name == "gpg" && slices.Contains(args, "--generate-key") {
		gnupgHome := envValue(env, "GNUPGHOME")
		revocations := filepath.Join(gnupgHome, "openpgp-revocs.d")
		if err := os.MkdirAll(revocations, 0o700); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(revocations, "test.rev"), []byte("test revocation\n"), 0o600); err != nil {
			return err
		}
	}
	for _, arg := range outputArgs(name, args) {
		if err := os.MkdirAll(filepath.Dir(arg), 0o700); err != nil {
			return err
		}
		body := "test artifact\n"
		if name == "minisign" {
			body = "untrusted comment: minisign default test comment\nencoded-test-artifact\n"
		}
		if err := os.WriteFile(arg, []byte(body), 0o600); err != nil {
			return err
		}
	}
	return nil
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
		Tool:   "decernor",
		Out:    root,
		Runner: runner,
		Now:    func() time.Time { return time.Date(2026, 7, 5, 18, 0, 0, 0, time.UTC) },
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

	hasGPG := false
	hasMinisign := false
	hasSSH := false
	for _, call := range runner.calls {
		hasGPG = hasGPG || call.name == "gpg"
		hasMinisign = hasMinisign || call.name == "minisign"
		hasSSH = hasSSH || call.name == "ssh-keygen"
	}
	if !hasGPG || !hasMinisign || !hasSSH {
		t.Fatalf("expected gpg/minisign/ssh-keygen calls; got %#v", runner.calls)
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
