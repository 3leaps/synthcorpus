//go:build sidecars

package provability

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSidecarGPGImportLeavesEmptyRings(t *testing.T) {
	gpg := mustCapableGPG(t)
	root, err := FixturesRoot()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range FixturesWithProof(ProofGPGImportEmptyRings) {
		f := f
		t.Run(f.Rel, func(t *testing.T) {
			home := t.TempDir()
			ctx, cancel := context.WithTimeout(context.Background(), helperTimeout)
			defer cancel()
			cmd := exec.CommandContext(ctx, gpg, "--batch", "--yes", "--homedir", home, "--import", filepath.Join(root, f.Rel))
			err := cmd.Run()
			if err == nil {
				t.Fatal("gpg --import unexpectedly succeeded")
			}
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				t.Fatal("gpg import timeout")
			}
			var exitErr *exec.ExitError
			if !errors.As(err, &exitErr) {
				t.Fatalf("expected ExitError from started gpg, got %T: %v", err, err)
			}
			assertEmptyColonRings(t, gpg, home)
		})
	}
}

func TestSidecarSSHRejects(t *testing.T) {
	sshKeygen := mustCapableSSHKeygen(t)
	root, err := FixturesRoot()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range FixturesWithProof(ProofSSHKeygenL) {
		f := f
		t.Run("l/"+f.Rel, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), helperTimeout)
			defer cancel()
			cmd := exec.CommandContext(ctx, sshKeygen, "-l", "-f", filepath.Join(root, f.Rel))
			err := cmd.Run()
			requireHelperExitReject(t, ctx, err, "ssh-keygen -l")
		})
	}
	for _, f := range FixturesWithProof(ProofSSHKeygenY) {
		f := f
		t.Run("y/"+f.Rel, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(root, f.Rel))
			if err != nil {
				t.Fatal(err)
			}
			tmp := filepath.Join(t.TempDir(), "key")
			if err := os.WriteFile(tmp, data, 0o600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), helperTimeout)
			defer cancel()
			cmd := exec.CommandContext(ctx, sshKeygen, "-y", "-f", tmp)
			err = cmd.Run()
			requireHelperExitReject(t, ctx, err, "ssh-keygen -y")
		})
	}
}

func TestSidecarMinisignRejects(t *testing.T) {
	minisign := mustCapableMinisign(t)
	root, err := FixturesRoot()
	if err != nil {
		t.Fatal(err)
	}
	msg := filepath.Join(t.TempDir(), "msg.txt")
	if err := os.WriteFile(msg, []byte("synthcorpus provability probe\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, f := range FixturesWithProof(ProofMinisignSignReject) {
		f := f
		t.Run("sign/"+f.Rel, func(t *testing.T) {
			sig := filepath.Join(t.TempDir(), "out.minisig")
			ctx, cancel := context.WithTimeout(context.Background(), helperTimeout)
			defer cancel()
			cmd := exec.CommandContext(ctx, minisign, "-S", "-s", filepath.Join(root, f.Rel), "-m", msg, "-x", sig)
			cmd.Stdin = strings.NewReader("\n")
			err := cmd.Run()
			requireHelperExitReject(t, ctx, err, "minisign -S")
		})
	}
	for _, f := range FixturesWithProof(ProofMinisignVerifyReject) {
		f := f
		t.Run("verify/"+f.Rel, func(t *testing.T) {
			sig := filepath.Join(t.TempDir(), "msg.minisig")
			if err := os.WriteFile(sig, []byte("untrusted comment: signature from synthcorpus probe\nRWQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), helperTimeout)
			defer cancel()
			cmd := exec.CommandContext(ctx, minisign, "-V", "-p", filepath.Join(root, f.Rel), "-m", msg, "-x", sig)
			err := cmd.Run()
			requireHelperExitReject(t, ctx, err, "minisign -V")
		})
	}
}

func TestSidecarWrongHelperShimsFailCapability(t *testing.T) {
	// Deterministic: place exit-1 shims first on PATH; capability must fail for each family.
	dir := t.TempDir()
	for _, name := range []string{"gpg", "minisign", "ssh-keygen"} {
		path := filepath.Join(dir, name)
		// Startable, exits 1, no identity output.
		if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 1\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	if _, err := resolveHelper("gpg"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	r := OSRunner{}
	gpgPath, _ := resolveHelper("gpg")
	if err := probeGPG(ctx, r, gpgPath); err == nil {
		t.Fatal("gpg capability must fail for exit-only shim")
	}
	msPath, _ := resolveHelper("minisign")
	if err := probeMinisign(ctx, r, msPath); err == nil {
		t.Fatal("minisign capability must fail for exit-only shim")
	}
	sshPath, _ := resolveHelper("ssh-keygen")
	if err := probeSSHKeygen(ctx, r, sshPath); err == nil {
		t.Fatal("ssh-keygen capability must fail for exit-only shim")
	}
}

func assertEmptyColonRings(t *testing.T, gpg, home string) {
	t.Helper()
	for _, mode := range []string{"--list-keys", "--list-secret-keys"} {
		ctx, cancel := context.WithTimeout(context.Background(), helperTimeout)
		cmd := exec.CommandContext(ctx, gpg, "--batch", "--homedir", home, "--with-colons", mode)
		out, err := cmd.CombinedOutput()
		timedOut := errors.Is(ctx.Err(), context.DeadlineExceeded)
		cancel()
		if timedOut {
			t.Fatalf("%s timeout", mode)
		}
		// Supported GnuPG: empty rings list successfully (exit 0). Nonzero is infrastructure failure.
		if err != nil {
			t.Fatalf("%s must succeed on empty ring after failed import: %v (%s)", mode, err, out)
		}
		if colonKeyringHasKeys(string(out)) {
			t.Fatalf("%s shows key material after failed import:\n%s", mode, out)
		}
	}
}

func mustCapableGPG(t *testing.T) string {
	t.Helper()
	path, err := resolveHelper("gpg")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), helperTimeout)
	defer cancel()
	if err := probeGPG(ctx, OSRunner{}, path); err != nil {
		t.Fatal(err)
	}
	return path
}

func mustCapableMinisign(t *testing.T) string {
	t.Helper()
	path, err := resolveHelper("minisign")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), helperTimeout)
	defer cancel()
	if err := probeMinisign(ctx, OSRunner{}, path); err != nil {
		t.Fatal(err)
	}
	return path
}

func mustCapableSSHKeygen(t *testing.T) string {
	t.Helper()
	path, err := resolveHelper("ssh-keygen")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), helperTimeout)
	defer cancel()
	if err := probeSSHKeygen(ctx, OSRunner{}, path); err != nil {
		t.Fatal(err)
	}
	return path
}

func requireHelperExitReject(t *testing.T, ctx context.Context, err error, label string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s unexpectedly succeeded", label)
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		t.Fatalf("%s infrastructure timeout", label)
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("%s expected ExitError from started helper, got %T: %v", label, err, err)
	}
}
