package generator

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

// Required sidecars for the generated-real lane (impl-plan §9).
// gpgconf is required so deep GNUPGHOME paths can create a short agent socketdir.
var requiredSidecars = []string{"gpg", "gpgconf", "minisign", "ssh-keygen"}

// SidecarProbe injects PATH lookup and non-mutating capability probes so unit
// tests can supply fake executables without real crypto tooling.
type SidecarProbe struct {
	LookPath func(file string) (string, error)
	// Run executes path with args and returns combined stdout+stderr.
	// Non-zero exit should return err (typically *exec.ExitError) with output.
	Run func(ctx context.Context, path string, args ...string) (output string, err error)
}

func defaultSidecarProbe() SidecarProbe {
	return SidecarProbe{
		LookPath: exec.LookPath,
		Run: func(ctx context.Context, path string, args ...string) (string, error) {
			cmd := exec.CommandContext(ctx, path, args...)
			out, err := cmd.CombinedOutput()
			return string(out), err
		},
	}
}

// DefaultSidecarPreflight probes every required helper before any output
// mutation or mint. Presence alone is insufficient: each binary must execute
// a non-mutating version/capability invocation successfully.
func DefaultSidecarPreflight(ctx context.Context) error {
	return RunSidecarPreflight(ctx, defaultSidecarProbe())
}

// RunSidecarPreflight is the testable implementation of DefaultSidecarPreflight.
func RunSidecarPreflight(ctx context.Context, probe SidecarProbe) error {
	if probe.LookPath == nil {
		probe.LookPath = exec.LookPath
	}
	if probe.Run == nil {
		return errors.New("sidecar probe Run is required")
	}

	paths := make(map[string]string, len(requiredSidecars))
	var missing []string
	for _, name := range requiredSidecars {
		p, err := probe.LookPath(name)
		if err != nil {
			missing = append(missing, name)
			continue
		}
		paths[name] = p
	}
	if len(missing) > 0 {
		return fmt.Errorf("required sidecars not found on PATH: %s (install gpg≥2.4, gpgconf, minisign, and OpenSSH ssh-keygen)", strings.Join(missing, ", "))
	}

	if err := probeGPG(ctx, probe, paths["gpg"]); err != nil {
		return err
	}
	if err := probeGPGConf(ctx, probe, paths["gpgconf"]); err != nil {
		return err
	}
	if err := probeMinisign(ctx, probe, paths["minisign"]); err != nil {
		return err
	}
	if err := probeSSHKeygen(ctx, probe, paths["ssh-keygen"]); err != nil {
		return err
	}
	return nil
}

func probeGPG(ctx context.Context, probe SidecarProbe, path string) error {
	out, err := probe.Run(ctx, path, "--version")
	if err != nil {
		return fmt.Errorf("gpg capability probe failed (%s --version): %w\n%s", path, err, strings.TrimSpace(out))
	}
	ver, err := parseGPGVersion(out)
	if err != nil {
		return fmt.Errorf("gpg version parse failed: %w", err)
	}
	if !versionAtLeast(ver, [3]int{2, 4, 0}) {
		return fmt.Errorf("gpg version %s is below required minimum 2.4.0 (found via gpg --version)", formatVersion(ver))
	}
	return nil
}

func probeGPGConf(ctx context.Context, probe SidecarProbe, path string) error {
	// Non-mutating; proves the binary executes and is the GnuPG gpgconf.
	out, err := probe.Run(ctx, path, "--version")
	if err != nil {
		return fmt.Errorf("gpgconf capability probe failed (%s --version): %w\n%s", path, err, strings.TrimSpace(out))
	}
	lower := strings.ToLower(out)
	if !strings.Contains(lower, "gpg") && !strings.Contains(lower, "gnupg") {
		return fmt.Errorf("gpgconf capability probe returned unexpected output (want GnuPG gpgconf): %q", strings.TrimSpace(out))
	}
	return nil
}

func probeMinisign(ctx context.Context, probe SidecarProbe, path string) error {
	// minisign -v prints version; treat successful execution as capability OK.
	out, err := probe.Run(ctx, path, "-v")
	if err != nil {
		// Some builds print version on stderr and exit non-zero; accept if output names minisign.
		if strings.Contains(strings.ToLower(out), "minisign") {
			return nil
		}
		return fmt.Errorf("minisign capability probe failed (%s -v): %w\n%s", path, err, strings.TrimSpace(out))
	}
	if !strings.Contains(strings.ToLower(out), "minisign") && !containsDigit(out) {
		return fmt.Errorf("minisign capability probe returned unexpected output: %q", strings.TrimSpace(out))
	}
	return nil
}

// invalidSSHKeyType is an intentionally invalid -t value. OpenSSH responds
// with "unknown key type …" without entering interactive key generation.
// (Bare `ssh-keygen` on macOS starts interactive generation — never probe that way.)
const invalidSSHKeyType = "__synthcorpus_invalid_key_type__"

func probeSSHKeygen(ctx context.Context, probe SidecarProbe, path string) error {
	out, err := probe.Run(ctx, path, "-t", invalidSSHKeyType)
	lower := strings.ToLower(out)

	// Hard reject any interactive generation path (macOS no-args behavior).
	if strings.Contains(lower, "enter file") ||
		strings.Contains(lower, "generating public/private") ||
		strings.Contains(lower, "enter passphrase") {
		return fmt.Errorf("ssh-keygen capability probe became interactive (refusing); output=%q", strings.TrimSpace(out))
	}

	if errors.Is(err, exec.ErrNotFound) || isExecFormatError(err, out) {
		return fmt.Errorf("ssh-keygen capability probe failed (binary not executable on this platform): %w\n%s", err, strings.TrimSpace(out))
	}

	// Accept known non-interactive diagnostics from OpenSSH (exit code varies by platform).
	if strings.Contains(lower, "unknown key type") ||
		strings.Contains(lower, "unsupported") ||
		strings.Contains(lower, "usage:") ||
		strings.Contains(lower, "invalid") {
		return nil
	}
	if err == nil {
		// Some builds exit 0 after printing unknown key type.
		return nil
	}
	return fmt.Errorf("ssh-keygen capability probe failed: %w\n%s", err, strings.TrimSpace(out))
}

func isExecFormatError(err error, out string) bool {
	msg := strings.ToLower(err.Error() + " " + out)
	return strings.Contains(msg, "exec format") ||
		strings.Contains(msg, "bad cpu type") ||
		strings.Contains(msg, "cannot execute") ||
		strings.Contains(msg, "not a valid")
}

func containsDigit(s string) bool {
	for _, r := range s {
		if r >= '0' && r <= '9' {
			return true
		}
	}
	return false
}

func parseGPGVersion(output string) ([3]int, error) {
	// First non-empty line is typically: gpg (GnuPG) 2.4.5
	// or: gpg (GnuPG) 2.4.5-unknown
	var zero [3]int
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		// Prefer the last whitespace-separated token that looks like a version.
		for i := len(fields) - 1; i >= 0; i-- {
			if fields[i][0] >= '0' && fields[i][0] <= '9' {
				return parseVersionTriplet(fields[i])
			}
		}
		return zero, fmt.Errorf("could not parse gpg version from line: %q", line)
	}
	return zero, fmt.Errorf("could not parse gpg version from: %q", strings.TrimSpace(output))
}

func parseVersionTriplet(raw string) ([3]int, error) {
	var zero [3]int
	// strip trailing junk: 2.4.5-unknown → 2.4.5
	raw = strings.TrimSpace(raw)
	if i := strings.IndexAny(raw, "-+_"); i >= 0 {
		raw = raw[:i]
	}
	parts := strings.Split(raw, ".")
	if len(parts) < 2 {
		return zero, fmt.Errorf("invalid version %q", raw)
	}
	var ver [3]int
	for i := 0; i < 3 && i < len(parts); i++ {
		n, err := strconv.Atoi(parts[i])
		if err != nil {
			return zero, fmt.Errorf("invalid version component %q in %q", parts[i], raw)
		}
		ver[i] = n
	}
	return ver, nil
}

func versionAtLeast(have, want [3]int) bool {
	for i := 0; i < 3; i++ {
		if have[i] > want[i] {
			return true
		}
		if have[i] < want[i] {
			return false
		}
	}
	return true
}

func formatVersion(v [3]int) string {
	return fmt.Sprintf("%d.%d.%d", v[0], v[1], v[2])
}
