package generator

import (
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

// Required sidecars for the generated-real lane (impl-plan §9).
// gpgconf is required so deep GNUPGHOME paths can create a short agent socketdir.
var requiredSidecars = []string{"gpg", "gpgconf", "minisign", "ssh-keygen"}

// DefaultSidecarPreflight checks PATH presence and minimum versions before any
// output mutation or mint. Clear install diagnostics; fail closed.
func DefaultSidecarPreflight(ctx context.Context) error {
	missing := make([]string, 0)
	for _, name := range requiredSidecars {
		if _, err := exec.LookPath(name); err != nil {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("required sidecars not found on PATH: %s (install gpg≥2.4, gpgconf, minisign, and OpenSSH ssh-keygen)", strings.Join(missing, ", "))
	}

	out, err := exec.CommandContext(ctx, "gpg", "--version").CombinedOutput()
	if err != nil {
		return fmt.Errorf("gpg --version failed: %w\n%s", err, strings.TrimSpace(string(out)))
	}
	ver, err := parseGPGVersion(string(out))
	if err != nil {
		return err
	}
	if !versionAtLeast(ver, [3]int{2, 4, 0}) {
		return fmt.Errorf("gpg version %s is below required minimum 2.4.0 (found via gpg --version)", formatVersion(ver))
	}
	return nil
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
