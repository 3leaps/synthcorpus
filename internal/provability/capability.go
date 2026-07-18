package provability

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

const helperTimeout = 15 * time.Second

// CommandRunner runs an external command (injectable for shim regressions).
type CommandRunner interface {
	// Run executes name with args; returns combined stdout+stderr and error.
	Run(ctx context.Context, name string, args ...string) (combined []byte, err error)
}

// OSRunner is the production CommandRunner.
type OSRunner struct{}

func (OSRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	return buf.Bytes(), err
}

// ValidateGPGCapability requires a successful GnuPG version identity.
func ValidateGPGCapability(out []byte, err error) error {
	if err != nil {
		return fmt.Errorf("gpg capability: expected success, got %v (%s)", err, out)
	}
	if !bytes.Contains(out, []byte("gpg (GnuPG)")) {
		return fmt.Errorf("gpg capability: missing GnuPG identity in output %q", out)
	}
	return nil
}

// ValidateMinisignCapability requires a successful minisign version line.
func ValidateMinisignCapability(out []byte, err error) error {
	if err != nil {
		return fmt.Errorf("minisign capability: expected success, got %v (%s)", err, out)
	}
	if !bytes.Contains(bytes.ToLower(out), []byte("minisign")) {
		return fmt.Errorf("minisign capability: missing minisign identity in output %q", out)
	}
	return nil
}

// ValidateSSHKeygenCapability requires a noninteractive unknown-type diagnostic.
// Real OpenSSH exits nonzero and prints "unknown key type"; bare exit-1 shims fail.
func ValidateSSHKeygenCapability(out []byte, err error) error {
	if err == nil {
		return errors.New("ssh-keygen capability: expected nonzero exit for invalid key type probe")
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		return fmt.Errorf("ssh-keygen capability: start failure: %v (%s)", err, out)
	}
	lower := strings.ToLower(string(out))
	if !strings.Contains(lower, "unknown key type") && !strings.Contains(lower, "is not a key type") {
		return fmt.Errorf("ssh-keygen capability: missing unknown-key-type diagnostic in %q", out)
	}
	return nil
}

func resolveHelper(name string) (string, error) {
	path, err := exec.LookPath(name)
	if err != nil {
		return "", fmt.Errorf("%s required: %w", name, err)
	}
	return path, nil
}

func probeGPG(ctx context.Context, r CommandRunner, path string) error {
	out, err := r.Run(ctx, path, "--version")
	return ValidateGPGCapability(out, err)
}

func probeMinisign(ctx context.Context, r CommandRunner, path string) error {
	out, err := r.Run(ctx, path, "-v")
	return ValidateMinisignCapability(out, err)
}

func probeSSHKeygen(ctx context.Context, r CommandRunner, path string) error {
	out, err := r.Run(ctx, path, "-t", "__synthcorpus_invalid_key_type__")
	return ValidateSSHKeygenCapability(out, err)
}
