// Package decernorloc resolves a decernor binary for drift-check tooling.
//
// Dependency direction is one-way: synthcorpus locates a built decernor by
// absolute path or PATH lookup. It never walks to a sibling worktree.
package decernorloc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode"
)

const (
	// EnvBinary is the preferred absolute path to a decernor binary.
	EnvBinary = "DECERNOR_BIN"
	// DefaultBinaryName is the PATH basename when EnvBinary is unset.
	DefaultBinaryName = "decernor"
	// MinCommitSHALen is the minimum hex length accepted for pin/identity commits.
	// Short ambiguous prefixes (e.g. "c") must not satisfy a preferred pin.
	MinCommitSHALen = 7
	// Expected pin schema markers.
	pinSchemaVersion = "v0"
	pinKind          = "synthcorpus-decernor-pin"
	pinConsumer      = "synthcorpus"
	pinTool          = "decernor"
)

// Pin is the machine-readable consumer pin (manifests/decernor-pin.json).
type Pin struct {
	SchemaVersion   string `json:"schema_version"`
	Kind            string `json:"kind"`
	Consumer        string `json:"consumer"`
	Tool            string `json:"tool"`
	MinVersion      string `json:"min_version"`
	PreferredTag    string `json:"preferred_tag,omitempty"`
	PreferredCommit string `json:"preferred_commit"`
	SourceRepo      string `json:"source_repo"`
	Notes           string `json:"notes,omitempty"`
	Locate          Locate `json:"locate"`
}

// Locate describes how to find the consumer binary.
type Locate struct {
	Env       string   `json:"env"`
	PathNames []string `json:"path_names"`
}

// Identity is parsed from `decernor version -e` (stdout only).
type Identity struct {
	Path    string
	Version string
	Commit  string
}

// LoadPin reads and validates a pin JSON file.
// Missing schema/kind/tool/consumer, min_version, or preferred_commit fails closed.
func LoadPin(path string) (Pin, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Pin{}, err
	}
	var pin Pin
	if err := json.Unmarshal(data, &pin); err != nil {
		return Pin{}, fmt.Errorf("parse pin: %w", err)
	}
	if err := validatePin(pin); err != nil {
		return Pin{}, err
	}
	// Defaults only after required fields are present.
	if pin.Locate.Env == "" {
		pin.Locate.Env = EnvBinary
	}
	if len(pin.Locate.PathNames) == 0 {
		pin.Locate.PathNames = []string{DefaultBinaryName}
	}
	return pin, nil
}

func validatePin(pin Pin) error {
	if pin.SchemaVersion != pinSchemaVersion {
		return fmt.Errorf("pin schema_version %q (want %q)", pin.SchemaVersion, pinSchemaVersion)
	}
	if pin.Kind != pinKind {
		return fmt.Errorf("pin kind %q (want %q)", pin.Kind, pinKind)
	}
	if pin.Consumer != pinConsumer {
		return fmt.Errorf("pin consumer %q (want %q)", pin.Consumer, pinConsumer)
	}
	if pin.Tool != pinTool {
		return fmt.Errorf("pin tool %q (want %q)", pin.Tool, pinTool)
	}
	if strings.TrimSpace(pin.MinVersion) == "" {
		return errors.New("pin min_version is required")
	}
	if _, err := parseDottedVersion(pin.MinVersion); err != nil {
		return fmt.Errorf("pin min_version: %w", err)
	}
	if err := validateCommitSHA(pin.PreferredCommit, "preferred_commit"); err != nil {
		return err
	}
	if pin.PreferredTag != "" && !validReleaseTag(pin.PreferredTag) {
		return fmt.Errorf("pin preferred_tag %q is not a vMAJOR.MINOR.PATCH tag", pin.PreferredTag)
	}
	return nil
}

func validReleaseTag(tag string) bool {
	tag = strings.TrimSpace(tag)
	if !strings.HasPrefix(tag, "v") {
		return false
	}
	_, err := parseDottedVersion(strings.TrimPrefix(tag, "v"))
	return err == nil
}

// LocateBinary resolves the decernor executable.
// Order: explicit path argument, then pin/env DECERNOR_BIN, then PATH names.
// Relative paths and ".." segments are rejected.
func LocateBinary(explicit string, pin Pin) (string, error) {
	candidates := make([]string, 0, 4)
	if strings.TrimSpace(explicit) != "" {
		candidates = append(candidates, explicit)
	}
	envName := pin.Locate.Env
	if envName == "" {
		envName = EnvBinary
	}
	if v := strings.TrimSpace(os.Getenv(envName)); v != "" {
		candidates = append(candidates, v)
	}
	for _, name := range pin.Locate.PathNames {
		if name == "" {
			continue
		}
		if path, err := exec.LookPath(name); err == nil {
			candidates = append(candidates, path)
		}
	}
	var errs []string
	for _, c := range candidates {
		abs, err := authorizeBinaryPath(c)
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		return abs, nil
	}
	if len(errs) > 0 {
		return "", fmt.Errorf("decernor binary not usable: %s", strings.Join(errs, "; "))
	}
	return "", errors.New("decernor binary not found: set DECERNOR_BIN or install decernor on PATH")
}

func authorizeBinaryPath(path string) (string, error) {
	if path == "" {
		return "", errors.New("empty path")
	}
	if !filepath.IsAbs(path) {
		// Allow bare PATH basenames only after LookPath; reject relative guesses.
		if strings.Contains(path, string(filepath.Separator)) || strings.Contains(path, "..") {
			return "", fmt.Errorf("refusing relative decernor path %q (use absolute DECERNOR_BIN)", path)
		}
	}
	if strings.Contains(path, "..") {
		return "", fmt.Errorf("refusing path with .. segment: %s", path)
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(abs)
	if err != nil {
		return "", err
	}
	if info.IsDir() {
		return "", fmt.Errorf("decernor path is a directory: %s", abs)
	}
	return abs, nil
}

// ReadIdentity runs `decernor version -e` and parses Version/Commit lines.
// Both Version and a usable Commit are required (commit is the primary soft pin).
func ReadIdentity(ctx context.Context, binary string) (Identity, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, binary, "version", "-e")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return Identity{}, fmt.Errorf("run %s version -e: %w (%s)", binary, err, strings.TrimSpace(stderr.String()))
	}
	id := Identity{Path: binary}
	for _, line := range strings.Split(stdout.String(), "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "Version:"):
			id.Version = strings.TrimSpace(strings.TrimPrefix(line, "Version:"))
		case strings.HasPrefix(line, "Commit:"):
			id.Commit = strings.TrimSpace(strings.TrimPrefix(line, "Commit:"))
		}
	}
	if id.Version == "" {
		return Identity{}, fmt.Errorf("could not parse Version from %s version -e", binary)
	}
	if err := validateCommitSHA(id.Commit, "identity commit"); err != nil {
		return Identity{}, fmt.Errorf("could not parse usable Commit from %s version -e: %w", binary, err)
	}
	return id, nil
}

// CheckPin ensures the binary identity meets the soft pin.
// Commit is required on both sides; identity commit must equal the pin or be a
// longer unambiguous prefix extension of the preferred commit (never the reverse).
func CheckPin(id Identity, pin Pin) error {
	if err := validatePin(pin); err != nil {
		return err
	}
	if _, err := parseDottedVersion(id.Version); err != nil {
		return fmt.Errorf("identity version: %w", err)
	}
	if !versionAtLeast(id.Version, pin.MinVersion) {
		return fmt.Errorf("decernor version %q does not satisfy min_version %q", id.Version, pin.MinVersion)
	}
	if err := validateCommitSHA(id.Commit, "identity commit"); err != nil {
		return err
	}
	if !commitMatchesPreferred(id.Commit, pin.PreferredCommit) {
		return fmt.Errorf("decernor commit %q does not match preferred_commit %q", id.Commit, pin.PreferredCommit)
	}
	return nil
}

func validateCommitSHA(value, label string) error {
	value = strings.TrimSpace(strings.ToLower(value))
	if value == "" || value == "unknown" {
		return fmt.Errorf("%s is required (got %q)", label, value)
	}
	if len(value) < MinCommitSHALen {
		return fmt.Errorf("%s %q is shorter than minimum %d hex chars", label, value, MinCommitSHALen)
	}
	for _, r := range value {
		if !unicode.Is(unicode.ASCII_Hex_Digit, r) {
			return fmt.Errorf("%s %q is not a hex commit SHA", label, value)
		}
	}
	return nil
}

// commitMatchesPreferred requires identity to equal preferred, or to be a
// longer hex string that starts with the full preferred pin (pin is the shorter
// or equal side). A short identity prefix must never satisfy a longer pin.
func commitMatchesPreferred(identity, preferred string) bool {
	id := strings.ToLower(strings.TrimSpace(identity))
	pref := strings.ToLower(strings.TrimSpace(preferred))
	if id == pref {
		return true
	}
	// Identity may be a longer git describe object name that starts with pin.
	if len(id) > len(pref) && strings.HasPrefix(id, pref) {
		return true
	}
	return false
}

// parseDottedVersion accepts only complete dotted numeric components (e.g. 0.1.1).
// Prerelease/build suffixes and non-numeric tokens fail closed.
func parseDottedVersion(v string) ([]int, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil, errors.New("empty version")
	}
	parts := strings.Split(v, ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("version %q needs at least major.minor", v)
	}
	out := make([]int, len(parts))
	for i, p := range parts {
		if p == "" {
			return nil, fmt.Errorf("version %q has empty component", v)
		}
		for _, r := range p {
			if r < '0' || r > '9' {
				return nil, fmt.Errorf("version %q has non-numeric component %q", v, p)
			}
		}
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil, fmt.Errorf("version %q: %w", v, err)
		}
		out[i] = n
	}
	return out, nil
}

// versionAtLeast compares dotted numeric versions component-wise after full parse.
func versionAtLeast(have, want string) bool {
	hp, err := parseDottedVersion(have)
	if err != nil {
		return false
	}
	wp, err := parseDottedVersion(want)
	if err != nil {
		return false
	}
	n := len(hp)
	if len(wp) > n {
		n = len(wp)
	}
	for i := 0; i < n; i++ {
		h, w := 0, 0
		if i < len(hp) {
			h = hp[i]
		}
		if i < len(wp) {
			w = wp[i]
		}
		if h > w {
			return true
		}
		if h < w {
			return false
		}
	}
	return true
}
